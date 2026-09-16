rule PEiD_01676_PEtite_v1_2_ {
  meta:
    description = "[PEtite v1.2]"
    ep_only     = "true"

  strings:
    $a = { 9C 60 E8 CA ?? ?? ?? 03 ?? 04 ?? 05 ?? 06 ?? 07 ?? 08 }

  condition:
    $a
}