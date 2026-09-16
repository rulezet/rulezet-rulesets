rule PEiD_02356_Upack_0_22___0_23_beta____Dwing_ {
  meta:
    description = "[Upack 0.22 - 0.23 beta -> Dwing]"
    ep_only     = "false"

  strings:
    $a = { 6A 07 BE 88 01 40 00 AD 8B F8 59 95 F3 A5 AD B5 ?? F3 AB AD 50 97 51 58 8D 54 }

  condition:
    $a
}