rule PEiD_00611_EXECryptor_2_2_x____SoftComplete_Developement_ {
  meta:
    description = "[EXECryptor 2.2.x -> SoftComplete Developement]"
    ep_only     = "false"

  strings:
    $a = { E8 F7 FE FF FF 05 ?? ?? 00 00 FF E0 E8 EB FE FF FF 05 ?? ?? 00 00 FF E0 E8 04 00 00 00 FF FF FF FF }

  condition:
    $a
}