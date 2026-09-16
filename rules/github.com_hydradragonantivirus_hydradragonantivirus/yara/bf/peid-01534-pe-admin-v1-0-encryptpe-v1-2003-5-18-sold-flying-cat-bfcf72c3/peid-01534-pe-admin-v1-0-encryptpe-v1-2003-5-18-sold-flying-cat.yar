rule PEiD_01534_PE_Admin_V1_0__EncryptPE_V1_2003_5_18_Sold_____Flying_Cat_ {
  meta:
    description = "[PE_Admin V1.0 (EncryptPE V1.2003.5.18 Sold) -> Flying Cat]"
    ep_only     = "true"

  strings:
    $a = { 60 9C 64 FF 35 00 00 00 00 E8 79 01 00 00 90 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

  condition:
    $a
}