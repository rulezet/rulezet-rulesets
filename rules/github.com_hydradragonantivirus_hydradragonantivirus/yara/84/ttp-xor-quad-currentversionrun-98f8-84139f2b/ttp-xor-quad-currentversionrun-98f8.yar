rule TTP_XOR_QUAD_CurrentVersionRun_98f8 {
  strings:
    $key_98f8 = { cb 97 [2] ef 99 [2] c4 b5 [2] ea 97 [2] fe 8c [2] f1 96 [2] ef 8b [2] ed 8a [2] f6 8c [2] ea 8b [2] f6 a4 }

  condition:
    any of them
}