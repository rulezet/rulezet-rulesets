rule PEiD_02021_ROD_High_TECH____Ayman_ {
  meta:
    description = "[ROD High TECH -> Ayman]"
    ep_only     = "true"

  strings:
    $a = { 60 8B 15 1D 13 40 00 F7 E0 8D 82 83 19 00 00 E8 58 0C 00 00 }

  condition:
    $a
}