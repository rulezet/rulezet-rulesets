rule PEiD_01781_Program_Protector_XP_v1_0_ {
  meta:
    description = "[Program Protector XP v1.0]"
    ep_only     = "true"

  strings:
    $a = { E8 ?? ?? ?? ?? 58 83 D8 05 89 C3 81 C3 ?? ?? ?? ?? 8B 43 64 50 }

  condition:
    $a
}