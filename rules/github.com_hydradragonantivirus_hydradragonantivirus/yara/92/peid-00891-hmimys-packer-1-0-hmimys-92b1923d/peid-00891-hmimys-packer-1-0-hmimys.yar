rule PEiD_00891_hmimys_Packer_1_0____hmimys_ {
  meta:
    description = "[hmimys-Packer 1.0 -> hmimys]"
    ep_only     = "false"

  strings:
    $a = { 5E 83 C6 64 AD 50 AD 50 83 EE 6C AD 50 AD 50 AD 50 AD 50 AD 50 E8 E7 07 00 00 }

  condition:
    $a
}