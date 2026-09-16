rule PEiD_02109_SLVc0deProtector_1_1x____SLV___ICU_ {
  meta:
    description = "[SLVc0deProtector 1.1x -> SLV / ICU]"
    ep_only     = "true"

  strings:
    $a = { E8 00 00 00 00 58 C6 00 EB C6 40 01 08 FF E0 E9 4C ?? ?? 00 }

  condition:
    $a
}