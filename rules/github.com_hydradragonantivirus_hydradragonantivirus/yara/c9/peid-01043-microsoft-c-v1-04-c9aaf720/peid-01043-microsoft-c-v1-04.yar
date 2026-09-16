rule PEiD_01043_Microsoft_C_v1_04_ {
  meta:
    description = "[Microsoft C v1.04]"
    ep_only     = "true"

  strings:
    $a = { FA B8 ?? ?? 8E D8 8E D0 26 8B ?? ?? ?? 2B D8 F7 ?? ?? ?? 75 ?? B1 04 D3 E3 EB }

  condition:
    $a
}