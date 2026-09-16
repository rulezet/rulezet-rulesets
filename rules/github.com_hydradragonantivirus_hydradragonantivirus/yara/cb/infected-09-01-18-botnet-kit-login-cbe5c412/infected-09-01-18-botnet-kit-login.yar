rule infected_09_01_18_botnet_kit_login {
  meta:
    description = "botnet-kit - file login.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-09-01"
    hash1       = "6d9b953093ceb5af242f4cb813a4c5fe25f03840d31d063d4f90e342e695f4c3"

  strings:
    $s1  = "<form action=\"login.php\" method=\"post\">" fullword ascii
    $s2  = "<script src=\"http://code.jquery.com/jquery.js\"></script>" fullword ascii
    $s3  = "$password = $_POST['password'];" fullword ascii
    $s4  = "if (md5(\"randomsalt\".md5($password)) == $storedPassHash){" fullword ascii
    $s5  = "<!-- jQuery e plugin JavaScript  -->" fullword ascii
    $s6  = "<button type=\"submit\" class=\"btn btn-default\">LOGIN</button>" fullword ascii
    $s7  = "<input class=\"form-control\" placeholder=\"password\" type=\"password\" name=\"password\">" fullword ascii
    $s8  = "$content = fread($fp, filesize($filename));" fullword ascii
    $s9  = "setcookie(\"phash\", md5($password));" fullword ascii
    $s10 = "<link href=\"css/stili-custom.css\" rel=\"stylesheet\" media=\"screen\">" fullword ascii
    $s11 = "<label for=\"IP\">PASSWORD</label>" fullword ascii
    $s12 = "$storedPassHash = $content;" fullword ascii
    $s13 = "<!-- respond.js per IE8 -->" fullword ascii
    $s14 = "<link href=\"css/bootstrap.css\" rel=\"stylesheet\" media=\"screen\">" fullword ascii
    $s15 = "<script src=\"js/respond.min.js\"></script>" fullword ascii
    $s16 = "<script src=\"js/bootstrap.min.js\"></script>" fullword ascii
    $s17 = "<!-- Fogli di stile -->" fullword ascii
    $s18 = "<!-- Modernizr -->" fullword ascii
    $s19 = "error_reporting(E_ERROR | E_PARSE);" fullword ascii
    $s20 = "if ($password != \"\"){" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 7KB and
      (8 of them)
    ) or (all of them)
}