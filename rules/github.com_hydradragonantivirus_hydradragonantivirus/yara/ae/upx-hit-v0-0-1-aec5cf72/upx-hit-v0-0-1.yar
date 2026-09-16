import "pe"
rule UPX_HiT_v0_0_1 {
  strings:
    $a0 = { 94 BC ?? ?? ?? 00 B9 ?? 00 00 00 80 34 0C ?? E2 FA 94 FF E0 61 }

  condition:
    $a0 at pe.entry_point
}