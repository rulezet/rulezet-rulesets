import "pe"
rule Microsoft_Visual_Basic_v5_0 {
  strings:
    $a0 = { FF FF FF 00 00 00 00 00 00 30 00 00 00 40 00 00 00 00 00 00 }

  condition:
    $a0 at pe.entry_point
}