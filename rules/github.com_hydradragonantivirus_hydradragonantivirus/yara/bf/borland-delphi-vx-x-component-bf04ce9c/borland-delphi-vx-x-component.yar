import "pe"
rule Borland_Delphi_vx_x__Component_ {
  strings:
    $a0 = { C3 E9 ?? ?? ?? FF 8D 40 }

  condition:
    $a0 at pe.entry_point
}