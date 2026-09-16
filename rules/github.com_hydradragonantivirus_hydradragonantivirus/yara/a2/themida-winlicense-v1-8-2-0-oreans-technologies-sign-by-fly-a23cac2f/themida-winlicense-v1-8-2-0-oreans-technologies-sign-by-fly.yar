import "pe"
rule Themida_WinLicense_V1_8_2_0_______Oreans_Technologies_____Sign_By_fly {
  strings:
    $a0 = { B8 00 00 00 00 60 0B C0 74 68 E8 00 00 00 00 58 05 ?? 00 00 00 80 38 E9 75 ?? 61 EB ?? DB 2D ?? ?? ?? ?? FF FF FF FF FF FF FF FF 3D 40 E8 00 00 00 00 }

  condition:
    $a0 at pe.entry_point
}