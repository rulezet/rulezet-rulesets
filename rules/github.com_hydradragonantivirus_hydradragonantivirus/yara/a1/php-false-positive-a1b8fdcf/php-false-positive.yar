rule php_false_positive: WEBSHELL PROD {
  meta:
    description = "PHP false positives"
    license     = "https://creativecommons.org/licenses/by-nc/4.0/"
    author      = "Arnim Rupp"
    date        = "2021/01/14"

  strings:
            $gfp1  = "eval(\"return [$serialised_parameter"      $gfp2  = "$this->assert(strpos($styles, $"
    $gfp3  = "$module = new $_GET['module']($_GET['scope']);"
    $gfp4  = "$plugin->$_POST['action']($_POST['id']);"
    $gfp5  = "$_POST[partition_by]($_POST["
    $gfp6  = "$object = new $_REQUEST['type']($_REQUEST['id']);"
    $gfp7  = "The above example code can be easily exploited by passing in a string such as"      $gfp8  = "Smarty_Internal_Debug::start_render($_template);"
    $gfp9  = "?p4yl04d=UNION%20SELECT%20'<?%20system($_GET['command']);%20?>',2,3%20INTO%20OUTFILE%20'/var/www/w3bsh3ll.php"
    $gfp10 = "[][}{;|]\\|\\\\[+=]\\|<?=>?"
    $gfp11 = "(eval (getenv \"EPROLOG\")))"
    $gfp12 = "ZmlsZV9nZXRfY29udGVudHMoJ2h0dHA6Ly9saWNlbnNlLm9wZW5jYXJ0LWFwaS5jb20vbGljZW5zZS5waHA/b3JkZXJ"

  condition:
    any of ($gfp*)
}