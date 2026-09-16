rule PEiD_00949_KBys_Packer_0_28_Beta____Shoooo_ {
  meta:
    description = "[KBys Packer 0.28 Beta -> Shoooo]"
    ep_only     = "false"

  strings:
    $a = { 60 E8 00 00 00 00 5E 83 EE 0A 8B 06 03 C2 8B 08 89 4E F3 83 EE 0F 56 52 8B F0 AD AD 03 C2 8B D8 6A 04 BF 00 10 00 00 57 57 6A 00 FF 53 08 5A 59 BD 00 80 00 00 55 6A 00 50 51 52 50 89 06 AD AD 03 C2 50 AD 03 C2 FF D0 6A 04 57 AD 50 6A 00 FF 53 }

  condition:
    $a
}