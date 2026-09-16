import "pe"
rule PROTECT__EXE_COM_v6_0 {
  strings:
    $a0 = { 1E B4 30 CD 21 3C 02 73 ?? CD 20 BE ?? ?? E8 }

  condition:
    $a0 at pe.entry_point
}