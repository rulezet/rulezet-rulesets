import "pe"
rule PEStubOEP_v1_x {
  strings:
    $a0 = { 40 48 BE 00 ?? ?? 00 40 48 60 33 C0 B8 ?? ?? ?? 00 FF E0 C3 C3 }

  condition:
    $a0 at pe.entry_point
}