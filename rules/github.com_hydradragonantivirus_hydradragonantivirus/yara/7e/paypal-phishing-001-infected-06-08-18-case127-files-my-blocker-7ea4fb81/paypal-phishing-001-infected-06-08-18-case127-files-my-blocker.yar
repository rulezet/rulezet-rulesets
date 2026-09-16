rule PAYPAL_PHISHING_001_infected_06_08_18_case127_files_my_blocker {
  meta:
    description = "case127 - file blocker.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-06-08"
    hash1       = "4cdb5c239c8b72290a1ee526a844334c283baa4f4689a4d855a1814fe56c1996"

  strings:
    $s1  = "$host=$_GET['ip'];echo exec($host);" fullword ascii
    $s2  = "$hostname = gethostbyaddr($_SERVER['REMOTE_ADDR']);" fullword ascii
    $s3  = "') or strpos($_SERVER['HTTP_USER_AGENT'], 'bingbot') or strpos($_SERVER['HTTP_USER_AGENT'], 'crawler') or strpos($_SERVER['HTTP_" ascii
    $s4  = "if(strpos($_SERVER['HTTP_USER_AGENT'], 'google') or strpos($_SERVER['HTTP_USER_AGENT'], 'msnbot') or strpos($_SERVER['HTTP_USER_" ascii
    $s5  = "header(\"HTTP/1.0 404 Not Found\");" fullword ascii
    $s6  = "USER_AGENT'], 'PycURL') or strpos($_SERVER['HTTP_USER_AGENT'], 'facebookexternalhit') !== false) { header('HTTP/1.0 404 Not Foun" ascii
    $s7  = "if(strpos($_SERVER['HTTP_USER_AGENT'], 'google') or strpos($_SERVER['HTTP_USER_AGENT'], 'msnbot') or strpos($_SERVER['HTTP_USER_" ascii
    $s8  = "AGENT'], 'Yahoo! Slurp') or strpos($_SERVER['HTTP_USER_AGENT'], 'YahooSeeker') or strpos($_SERVER['HTTP_USER_AGENT'], 'Googlebot" ascii
    $s9  = "if (substr_count($hostname, $word) > 0) {" fullword ascii
    $s10 = "if(preg_match('/' . $ip . '/',$_SERVER['REMOTE_ADDR'])){" fullword ascii
    $s11 = "die(\"<h1>404 Not Found</h1>The page that you have requested could not be found.\");" fullword ascii
    $s12 = "$bannedIP = array(\"^66.102.*.*\", \"^38.100.*.*\", \"^107.170.*.*\", \"^149.20.*.*\", \"^38.105.*.*\", \"^74.125.*.*\",  \"^66." ascii
    $s13 = "if(in_array($_SERVER['REMOTE_ADDR'],$bannedIP)) {" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 7KB and
      (8 of them)
    ) or (all of them)
}