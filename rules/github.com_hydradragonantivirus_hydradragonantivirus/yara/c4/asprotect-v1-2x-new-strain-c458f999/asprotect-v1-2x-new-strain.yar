import "pe"
rule ASProtect_v1_2x__New_Strain_ {
  strings:
    $a0 = { 68 01 ?? ?? ?? E8 01 ?? ?? ?? C3 C3 }

  condition:
    $a0 at pe.entry_point
}