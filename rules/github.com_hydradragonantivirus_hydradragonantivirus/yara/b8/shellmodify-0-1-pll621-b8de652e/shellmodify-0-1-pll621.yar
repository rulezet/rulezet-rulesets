import "pe"
rule ShellModify_0_1____pll621 {
  strings:
    $a0 = { 55 8B EC 6A FF 68 98 66 41 00 68 3C 3D 41 00 64 A1 00 00 00 00 }

  condition:
    $a0 at pe.entry_point
}