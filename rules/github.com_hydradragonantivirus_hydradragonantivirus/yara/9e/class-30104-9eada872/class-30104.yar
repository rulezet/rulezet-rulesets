rule class_30104 {
  meta:
    description = "case109 - file class.30104.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-05-29"
    hash1       = "68a039f4da41a2afd11f54e340aff45878ab6b63a31c21ddcb128d539a7f0749"

  strings:
    $s1 = "<?php @assert($_POST['04p2l8p0']);?>" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 1KB and
      (all of them)
    ) or (all of them)
}