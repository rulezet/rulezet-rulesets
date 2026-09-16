rule PEiD_01564_PECompact_v1_20___v1_20_1_ {
  meta:
    description = "[PECompact v1.20 - v1.20.1]"
    ep_only     = "true"

  strings:
    $a = { EB 06 68 ?? ?? ?? ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 70 40 ?? 87 DD 8B 85 9A 70 40 }

  condition:
    $a
}