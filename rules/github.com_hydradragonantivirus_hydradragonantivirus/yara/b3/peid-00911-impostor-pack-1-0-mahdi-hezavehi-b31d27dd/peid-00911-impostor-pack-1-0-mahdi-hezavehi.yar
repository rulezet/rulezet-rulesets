rule PEiD_00911_IMPostor_Pack_1_0____Mahdi_Hezavehi_ {
  meta:
    description = "[IMPostor Pack 1.0 -> Mahdi Hezavehi]"
    ep_only     = "true"

  strings:
    $a = { BE ?? ?? ?? 00 83 C6 01 FF E6 00 00 00 00 ?? ?? 00 00 00 00 00 00 00 00 00 ?? ?? ?? 00 ?? 02 ?? ?? 00 10 00 00 00 02 00 }

  condition:
    $a
}