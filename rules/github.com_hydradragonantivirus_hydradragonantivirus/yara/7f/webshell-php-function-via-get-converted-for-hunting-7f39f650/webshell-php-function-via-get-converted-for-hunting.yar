rule webshell_php_function_via_get__converted_for_hunting: WEBSHELL HUNT_CONVERTED {
  meta:
    key   = "Webshell which sends eval/assert via GET"
    key   = "https://creativecommons.org/licenses/by-nc/4.0/"
    key   = "Arnim Rupp"
    key   = "2021/01/09"
    score = 40

  strings:
    $sr0   = /\$_GET\s?\[.{1,30}\]\(\$_GET\s?\[/ wide ascii
    $sr1   = /\$_POST\s?\[.{1,30}\]\(\$_GET\s?\[/ wide ascii
    $sr2   = /\$_POST\s?\[.{1,30}\]\(\$_POST\s?\[/ wide ascii
    $sr3   = /\$_GET\s?\[.{1,30}\]\(\$_POST\s?\[/ wide ascii
    $sr4   = /\$_REQUEST\s?\[.{1,30}\]\(\$_REQUEST\s?\[/ wide ascii
    $sr5   = /\$_SERVER\s?\[HTTP_.{1,30}\]\(\$_SERVER\s?\[HTTP_/ wide ascii
    $gfp1  = "eval(\"return [$serialised_parameter"
    $gfp2  = "$this->assert(strpos($styles, $"
    $gfp3  = "$module = new $_GET['module']($_GET['scope']);"
    $gfp4  = "$plugin->$_POST['action']($_POST['id']);"
    $gfp5  = "$_POST[partition_by]($_POST["
    $gfp6  = "$object = new $_REQUEST['type']($_REQUEST['id']);"
    $gfp7  = "The above example code can be easily exploited by passing in a string such as"
    $gfp8  = "Smarty_Internal_Debug::start_render($_template);"
    $gfp9  = "?p4yl04d=UNION%20SELECT%20'<?%20system($_GET['command']);%20?>',2,3%20INTO%20OUTFILE%20'/var/www/w3bsh3ll.php"
    $gfp10 = "[][}{;|]\\|\\\\[+=]\\|<?=>?"
    $gfp11 = "(eval (getenv \"EPROLOG\")))"
    $gfp12 = "ZmlsZV9nZXRfY29udGVudHMoJ2h0dHA6Ly9saWNlbnNlLm9wZW5jYXJ0LWFwaS5jb20vbGljZW5zZS5waHA/b3JkZXJ"

  condition:
    (filesize >= 500KB and filesize < 1500KB
    )
    and not (any of ($gfp*)) and any of ($sr*)
}