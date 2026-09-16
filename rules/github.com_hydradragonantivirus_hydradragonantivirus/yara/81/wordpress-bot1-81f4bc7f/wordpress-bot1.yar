rule wordpress_bot1 {
  meta:
    description = "07-04-19 - file wordpress-bot1.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2019-07-04"
    hash1       = "6a6eac7d84738c14320d18d43b8806a1f1c58b2e7693a9320ef97d89c3847527"

  strings:
        $s2 = "<?php"
    $s3 = "goto Foltw"
    $s4 = "$SsrUL < strlen($d38Ix)"
    $s5 = "foreach"

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 1000KB and
      (all of them)
    ) or (all of them)
}