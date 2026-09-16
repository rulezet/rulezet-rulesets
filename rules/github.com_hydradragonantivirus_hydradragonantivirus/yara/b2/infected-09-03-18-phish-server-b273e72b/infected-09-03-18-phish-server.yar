rule infected_09_03_18_phish_server {
  meta:
    description = "phish - file server.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-09-03"
    hash1       = "1c9066dd9b1d91a0cc9278629f7f0f8c7a6b9f9e0ebb1e739dd210f7a03ec025"

  strings:
    $s1 = "$ip_data = @json_decode(file_get_contents(\"http://www.geoplugin.net/json.gp?ip=\".$ip));" fullword ascii
    $s2 = "mail($own,$subj,$msg,$headers);" fullword ascii
    $s3 = "<?php"

  condition:
    (all of them)
}