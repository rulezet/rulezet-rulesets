rule PEiD_01479_PCPEC__alpha___preview__ {
  meta:
    description = "[PCPEC \"alpha - preview\"]"
    ep_only     = "true"

  strings:
    $a = { 53 51 52 56 57 55 E8 00 00 00 00 5D 8B CD 81 ED 33 30 40 00 }

  condition:
    $a
}