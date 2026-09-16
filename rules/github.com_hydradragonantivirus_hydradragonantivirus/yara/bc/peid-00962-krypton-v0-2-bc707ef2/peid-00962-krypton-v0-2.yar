rule PEiD_00962_Krypton_v0_2_ {
  meta:
    description = "[Krypton v0.2]"
    ep_only     = "true"

  strings:
    $a = { 8B 0C 24 E9 0A 7C 01 ?? AD 42 40 BD BE 9D 7A 04 }

  condition:
    $a
}