import "pe"
rule _Vx_Quake518_ {
  meta:
    description = "Vx: Quake.518"

  strings:
    $0 = { 1E 06 8C C8 8E D8 ?? ?? ?? ?? ?? ?? ?? B8 21 35 CD 21 81 }

  condition:
    $0 at pe.entry_point
}