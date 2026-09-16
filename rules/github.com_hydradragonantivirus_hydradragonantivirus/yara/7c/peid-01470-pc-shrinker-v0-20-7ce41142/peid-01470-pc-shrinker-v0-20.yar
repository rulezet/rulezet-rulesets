rule PEiD_01470_PC_Shrinker_v0_20_ {
  meta:
    description = "[PC Shrinker v0.20]"
    ep_only     = "true"

  strings:
    $a = { E8 E8 01 ?? ?? 60 01 AD B3 27 40 ?? 68 }

  condition:
    $a
}