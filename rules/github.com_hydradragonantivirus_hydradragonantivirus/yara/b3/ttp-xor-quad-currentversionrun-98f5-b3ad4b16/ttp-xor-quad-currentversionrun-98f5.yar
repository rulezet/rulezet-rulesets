rule TTP_XOR_QUAD_CurrentVersionRun_98f5 {
  strings:
    $key_98f5 = { cb 9a [2] ef 94 [2] c4 b8 [2] ea 9a [2] fe 81 [2] f1 9b [2] ef 86 [2] ed 87 [2] f6 81 [2] ea 86 [2] f6 a9 }

  condition:
    any of them
}