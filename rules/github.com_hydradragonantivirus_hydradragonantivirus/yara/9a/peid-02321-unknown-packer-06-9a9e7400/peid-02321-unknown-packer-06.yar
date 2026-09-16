rule PEiD_02321_Unknown_packer__06__ {
  meta:
    description = "[Unknown packer (06)]"
    ep_only     = "true"

  strings:
    $a = { FA B8 ?? ?? BE ?? ?? 33 F0 0E 17 2E ?? ?? ?? BA ?? ?? 87 E6 5B 33 DC }

  condition:
    $a
}