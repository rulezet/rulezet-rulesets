import "pe"
rule FSG_v1_0 {
  strings:
    $a0 = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? ?? 53 E8 0A 00 00 00 02 D2 75 05 8A 16 46 12 D2 C3 FC B2 80 A4 6A 02 5B }

  condition:
    $a0 at pe.entry_point
}