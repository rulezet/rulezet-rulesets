rule PEiD_02179_Symantec_Visual_Cafe_v3_0_ {
  meta:
    description = "[Symantec Visual Cafe v3.0]"
    ep_only     = "true"

  strings:
    $a = { 64 8B 05 ?? ?? ?? ?? 55 8B EC 6A FF 68 ?? ?? 40 ?? 68 ?? ?? 40 ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 08 50 53 56 57 89 65 E8 C7 45 FC }

  condition:
    $a
}