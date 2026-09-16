rule infected_09_30_18_Marvins {
  meta:
    description = "shell4 - file Marvins.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-09-30"
    hash1       = "421afe61a0801906370ba1819dfe7bbedb8dd098398592557de1cfa7f0ae90e6"

  strings:
    $s1 = "if(isset(" fullword ascii
    $s2 = "foreach($scandir" fullword ascii
    $s3 = "if(rmdir(" fullword ascii
    $s4 = "<?php" fullword ascii
    $s7 = "if(is_writable(\"$path/$file\") || !is_readable(\"$path/$file\")) echo '</font>';" fullword ascii

  condition:
    all of them
}