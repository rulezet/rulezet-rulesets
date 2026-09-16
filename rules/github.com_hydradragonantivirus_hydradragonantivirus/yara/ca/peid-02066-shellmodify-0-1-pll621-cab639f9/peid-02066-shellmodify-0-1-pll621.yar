rule PEiD_02066_ShellModify_0_1____pll621_ {
  meta:
    description = "[ShellModify 0.1 -> pll621]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 6A FF 68 98 66 41 00 68 3C 3D 41 00 64 A1 00 00 00 00 }

  condition:
    $a
}