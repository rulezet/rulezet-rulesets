rule PEiD_00490_Dropper_Creator_V0_1____Conflict_ {
  meta:
    description = "[Dropper Creator V0.1 -> Conflict]"
    ep_only     = "false"

  strings:
    $a = { 60 E8 00 00 00 00 5D 8D 05 ?? ?? ?? ?? 29 C5 8D 85 ?? ?? ?? ?? 31 C0 64 03 40 30 78 0C 8B 40 0C 8B 70 1C AD 8B 40 08 EB 09 }

  condition:
    $a
}