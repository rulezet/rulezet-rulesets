rule PEiD_02110_SLVc0deProtector_v1_1____SLV__h__ {
  meta:
    description = "[SLVc0deProtector v1.1 -> SLV (h)]"
    ep_only     = "true"

  strings:
    $a = { E8 00 00 00 00 58 C6 00 EB C6 40 01 08 FF E0 E9 4C }

  condition:
    $a
}