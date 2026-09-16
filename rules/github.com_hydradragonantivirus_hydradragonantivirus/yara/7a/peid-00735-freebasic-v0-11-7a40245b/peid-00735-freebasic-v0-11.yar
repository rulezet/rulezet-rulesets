rule PEiD_00735_FreeBASIC_v0_11_ {
  meta:
    description = "[FreeBASIC v0.11]"
    ep_only     = "true"

  strings:
    $a = { E8 ?? ?? 00 00 E8 01 00 00 00 C3 55 89 E5 }

  condition:
    $a
}