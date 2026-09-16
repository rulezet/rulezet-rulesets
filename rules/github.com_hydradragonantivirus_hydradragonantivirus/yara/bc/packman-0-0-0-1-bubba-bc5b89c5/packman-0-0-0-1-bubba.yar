import "pe"
rule Packman_0_0_0_1____bubba {
  strings:
    $a0 = { 60 E8 00 00 00 00 58 8D A8 ?? FE FF FF 8D 98 ?? ?? ?? FF 8D ?? ?? 01 00 00 }

  condition:
    $a0 at pe.entry_point
}