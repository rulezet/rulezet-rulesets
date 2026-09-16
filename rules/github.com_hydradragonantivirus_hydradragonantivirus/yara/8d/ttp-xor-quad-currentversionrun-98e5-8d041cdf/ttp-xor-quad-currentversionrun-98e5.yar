rule TTP_XOR_QUAD_CurrentVersionRun_98e5 {
  strings:
    $key_98e5 = { cb 8a [2] ef 84 [2] c4 a8 [2] ea 8a [2] fe 91 [2] f1 8b [2] ef 96 [2] ed 97 [2] f6 91 [2] ea 96 [2] f6 b9 }

  condition:
    any of them
}