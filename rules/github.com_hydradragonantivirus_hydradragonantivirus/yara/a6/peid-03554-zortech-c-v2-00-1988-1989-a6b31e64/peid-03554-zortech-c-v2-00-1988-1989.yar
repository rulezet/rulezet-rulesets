rule PEiD_03554_Zortech_C_v2_00_1988__1989_ {
  meta:
    description = "[Zortech C v2.00 1988, 1989]"
    ep_only     = "true"

  strings:
    $a = { FA B8 ?? ?? 8E D8 8C ?? ?? ?? 26 8B ?? ?? ?? 89 1E ?? ?? 8B D8 2B 1E ?? ?? 89 1E }

  condition:
    $a
}