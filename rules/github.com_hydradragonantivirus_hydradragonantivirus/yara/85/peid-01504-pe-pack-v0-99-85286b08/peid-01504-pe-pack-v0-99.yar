rule PEiD_01504_PE_Pack_v0_99_ {
  meta:
    description = "[PE Pack v0.99]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 ?? ?? ?? ?? 5D 83 ED 06 80 BD E0 04 ?? ?? 01 0F 84 F2 }

  condition:
    $a
}