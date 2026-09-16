import "pe"
rule TASM___MASM {
  strings:
    $a0 = { 6A 00 E8 ?? ?? 00 00 A3 ?? ?? 40 00 }

  condition:
    $a0 at pe.entry_point
}