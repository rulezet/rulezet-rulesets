rule PEiD_02034_SDC_1_2__Self_Decrypting_Binary_Generator____by_Claes_M_Nyberg_ {
  meta:
    description = "[SDC 1.2 (Self Decrypting Binary Generator) - by Claes M Nyberg]"
    ep_only     = "true"

  strings:
    $a = { 55 89 E5 83 EC 08 C7 04 24 01 00 00 00 FF 15 A0 91 40 00 E8 DB FE FF FF 55 89 E5 53 83 EC 14 8B 45 08 8B 00 8B 00 3D 91 00 00 C0 77 3B 3D 8D 00 00 C0 72 4B BB 01 00 00 00 C7 44 24 04 00 00 00 00 C7 04 24 08 00 00 00 E8 CE 24 00 00 83 F8 01 0F 84 C4 00 00 }

  condition:
    $a
}