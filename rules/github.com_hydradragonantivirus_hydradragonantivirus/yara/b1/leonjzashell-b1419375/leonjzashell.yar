rule leonjzashell {
  meta:
    description = "yertle - file leonjzashell.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-07-28"
    hash1       = "5f01b6d93673c9d1673aea513c51688b54e1c8c5c31e9770f6530c4dfdbc87dd"

  strings:
    $x1  = "Description: Execute Commands as the webserver you are serving wordpress with! Shell will probably live at /wp-content/plugi" fullword ascii
    $x2  = "Description: Execute Commands as the webserver you are serving wordpress with! Shell will probably live at /wp-content/plugins/s" ascii
    $s3  = "ns/shell/shell.php. Commands can be given using the 'cmd' GET parameter. Eg: \"http://192.168.0.1/wp-content/plugins/shell/shell" ascii
    $s4  = "Plugin URI: https://github.com/leonjza/wordpress-shell" fullword ascii
    $s5  = "# grab the command we want to run from the 'cmd' GET parameter" fullword ascii
    $s6  = "# Try to find a way to run our command using various PHP internals" fullword ascii
    $s7  = "# http://php.net/manual/en/function.system.php" fullword ascii
    $s8  = "php?cmd=id\", should provide you with output such as <code>uid=33(www-data) gid=verd33(www-data) groups=33(www-data)</code>" fullword ascii
    $s9  = "# http://php.net/manual/en/function.call-user-func-array.php" fullword ascii
    $s10 = "call_user_func_array('system', array($command));" fullword ascii
    $s11 = "# attempt to protect myself from deletion" fullword ascii
    $s12 = "# http://php.net/manual/en/function.call-user-func.php" fullword ascii
    $s13 = "call_user_func('system', $command);" fullword ascii
    $s14 = "$command = $_GET[\"cmd\"];" fullword ascii
    $s15 = "Plugin Name: Cheap & Nasty Wordpress Shell" fullword ascii
    $s16 = "system($command);" fullword ascii
    $s17 = "# http://php.net/manual/en/class.reflectionfunction.php" fullword ascii
    $s18 = "# has system() on a blacklist anyways :>" fullword ascii
    $s19 = "$function->invoke($command);" fullword ascii
    $s20 = "Author URI: https://leonjza.github.io" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 4KB and
      (1 of ($x*) and 4 of them)
    ) or (all of them)
}