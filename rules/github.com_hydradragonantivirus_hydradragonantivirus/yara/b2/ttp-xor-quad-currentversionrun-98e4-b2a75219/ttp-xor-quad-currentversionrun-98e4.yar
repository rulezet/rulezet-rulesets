rule TTP_XOR_QUAD_CurrentVersionRun_98e4 {
  strings:
    $key_98e4 = { cb 8b [2] ef 85 [2] c4 a9 [2] ea 8b [2] fe 90 [2] f1 8a [2] ef 97 [2] ed 96 [2] f6 90 [2] ea 97 [2] f6 b8 }

  condition:
    any of them
}