rule TTP_XOR_QUAD_CurrentVersionRun_984b {
  strings:
    $key_984b = { cb 24 [2] ef 2a [2] c4 06 [2] ea 24 [2] fe 3f [2] f1 25 [2] ef 38 [2] ed 39 [2] f6 3f [2] ea 38 [2] f6 17 }

  condition:
    any of them
}