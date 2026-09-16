rule uploader_wp_themes {
  meta:
    description = "PHP - file uploader_wp-themes.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2019-10-11"
    hash1       = "86f65fbbf9b9c2b96386d7206d1a7b064731244cc0b9b8a6e2fcb66a56e8f2a4"

  strings:
    $s1 = "<?php" fullword ascii
    $s2 = "error_reporting(0)" fullword ascii
    $s3 = "ignore_user_abort(1)" fullword ascii
    $s4 = "curl_exec($cur);" fullword ascii

  condition:
    (all of them)
}