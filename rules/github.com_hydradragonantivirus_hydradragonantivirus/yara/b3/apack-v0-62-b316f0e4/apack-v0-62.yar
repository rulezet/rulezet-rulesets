import "pe"
rule aPack_v0_62 {
  strings:
    $a0 = { 1E 06 8C C8 8E D8 ?? ?? ?? 8E C0 50 BE ?? ?? 33 FF FC B6 }

  condition:
    $a0 at pe.entry_point
}