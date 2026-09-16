rule PEiD_01721_PKLITE32_v1_1_ {
  meta:
    description = "[PKLITE32 v1.1]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 00 00 00 00 E8 }

  condition:
    $a
}