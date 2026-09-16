rule drupal_injection_case134 {
  meta:
    description = "case134 - file infection.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-06-15"
    hash1       = "85d567b960a8985678ca7fb34616a799db2183e50efa51e463b5ceaa92341e96"

  strings:
        $s2 = "error_reporting(0); @ini_set('error_log',NULL); @ini_set('log_errors',0); @ini_set('display_errors','Off'); @eval( base64_decode" ascii
    $s3 = "error_reporting(0); @ini_set('error_log',NULL); @ini_set('log_errors',0); @ini_set('display_errors','Off'); @eval( base64_decode" ascii

  condition:
    (uint16(0) == 0x7265 and
      filesize < 7KB and
      (all of them)
    ) or (all of them)
}