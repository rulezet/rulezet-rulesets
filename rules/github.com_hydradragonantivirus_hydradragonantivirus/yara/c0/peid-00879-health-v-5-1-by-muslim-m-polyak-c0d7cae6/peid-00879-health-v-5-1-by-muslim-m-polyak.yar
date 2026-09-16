rule PEiD_00879_HEALTH_v_5_1_by_Muslim_M_Polyak_ {
  meta:
    description = "[HEALTH v.5.1 by Muslim M.Polyak]"
    ep_only     = "true"

  strings:
    $a = { 1E E8 ?? ?? 2E 8C 06 ?? ?? 2E 89 3E ?? ?? 8B D7 B8 ?? ?? CD 21 8B D8 0E 1F E8 ?? ?? 06 57 A1 ?? ?? 26 }

  condition:
    $a
}