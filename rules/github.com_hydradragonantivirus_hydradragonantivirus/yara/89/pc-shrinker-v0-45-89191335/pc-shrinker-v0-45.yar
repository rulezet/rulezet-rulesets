import "pe"
rule PC_Shrinker_v0_45 {
  strings:
    $a0 = { BD ?? ?? ?? ?? 01 AD E3 38 40 ?? FF B5 DF 38 40 }

  condition:
    $a0 at pe.entry_point
}