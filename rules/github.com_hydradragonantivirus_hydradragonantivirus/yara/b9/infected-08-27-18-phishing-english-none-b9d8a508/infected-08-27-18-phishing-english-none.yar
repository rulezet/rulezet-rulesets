rule infected_08_27_18_phishing_english_none {
  meta:
    description = "english - file none.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-08-28"
    hash1       = "b687aff9a134b489ece3dd28cfe006a14718faa050e23827324581e8df514b49"

  strings:
    $s1 = "<?php"
    $s2 = "$ip_data = @json_decode(file_get_contents(\"http://www.geoplugin.net/json.gp?ip=\".$ip));" fullword ascii
    $s3 = "if (empty($login) || empty($passwd)) {" fullword ascii

  condition:
    (all of them)
}