rule TTP_XOR_QUAD_CurrentVersionRun_98e9 {
  strings:
    $key_98e9 = { cb 86 [2] ef 88 [2] c4 a4 [2] ea 86 [2] fe 9d [2] f1 87 [2] ef 9a [2] ed 9b [2] f6 9d [2] ea 9a [2] f6 b5 }

  condition:
    any of them
}