rule PEiD_01472_PC_Shrinker_v0_45_ {
  meta:
    description = "[PC Shrinker v0.45]"
    ep_only     = "true"

  strings:
    $a = { ?? BD ?? ?? ?? ?? 01 AD E3 38 40 ?? FF B5 DF 38 40 }

  condition:
    $a
}