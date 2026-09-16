import "pe"
rule MoleBox_V2_3X____MoleStudio_com_____Sign_By_fly {
  strings:
    $a0 = { E8 00 00 00 00 60 E8 4F 00 00 00 }

  condition:
    $a0 at pe.entry_point
}