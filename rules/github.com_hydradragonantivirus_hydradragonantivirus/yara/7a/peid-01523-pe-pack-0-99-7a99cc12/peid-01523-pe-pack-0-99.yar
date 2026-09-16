rule PEiD_01523_PE_PACK_0_99_ {
  meta:
    description = "[PE-PACK 0.99]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 00 00 00 00 5D 83 ED 06 80 BD E0 04 00 00 01 0F 84 F2 }

  condition:
    $a
}