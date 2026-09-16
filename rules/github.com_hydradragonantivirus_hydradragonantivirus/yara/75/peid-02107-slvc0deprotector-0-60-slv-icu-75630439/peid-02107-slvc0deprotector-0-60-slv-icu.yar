rule PEiD_02107_SLVc0deProtector_0_60____SLV___ICU_ {
  meta:
    description = "[SLVc0deProtector 0.60 -> SLV / ICU]"
    ep_only     = "false"

  strings:
    $a = { EB 02 FA 04 E8 49 00 00 00 69 E8 49 00 00 00 95 E8 4F 00 00 00 68 E8 1F 00 00 00 49 E8 E9 FF FF FF 67 E8 1F 00 00 00 93 E8 31 00 00 00 78 E8 DD }

  condition:
    $a
}