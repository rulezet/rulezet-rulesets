rule infected_09_10_18_phishing_smartsheet_data {
  meta:
    description = "account - file data.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-09-12"
    hash1       = "dee2198836643c8f440533264b416e648d51badc106824cc770cb431e3f26b0b"

  strings:
    $s1  = "$message .= \"Password: \".$_POST['passwd'].\"\\n\";" fullword ascii
    $s2  = "$message .= \"Username: \".$_POST['login'].\"\\n\";" fullword ascii
    $s3  = "\"User-Agent: \".$browser.\"\\n\";" fullword ascii
    $s4  = "$browser = $_SERVER['HTTP_USER_AGENT'];" fullword ascii
    $s5  = "$recipient = \"johnwashington1960@gmail.com\";" fullword ascii
    $s6  = "} elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) { " fullword ascii
    $s7  = "//get user's ip address " fullword ascii
    $s8  = "$ip = $_SERVER['HTTP_X_FORWARDED_FOR']; " fullword ascii
    $s9  = "$hostname = gethostbyaddr($ip);" fullword ascii
    $s10 = "$headers .= \"MIME-Version: 1.0\\n\";" fullword ascii
    $s11 = "if (mail($recipient,$subject,$message,$headers))" fullword ascii
    $s12 = "$ip = getenv(\"REMOTE_ADDR\");" fullword ascii
    $s13 = "$message .= \"HostName : \".$hostname.\"\\n\";" fullword ascii
    $s14 = "$headers .= $_POST['eMailAdd'].\"\\n\";" fullword ascii
    $s15 = "header(\"Location: index3.php\");" fullword ascii
    $s16 = "$headers = \"From: OFFBox\";" fullword ascii
    $s17 = "if (!empty($_SERVER['HTTP_CLIENT_IP'])) { " fullword ascii
    $s18 = "$ip = $_SERVER['HTTP_CLIENT_IP']; " fullword ascii
    $s19 = "\"Country Code: {$geoplugin->countryCode}\\n\";" fullword ascii
    $s20 = "$message .= \"======================================\\n\";" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 4KB and
      (8 of them)
    ) or (all of them)
}