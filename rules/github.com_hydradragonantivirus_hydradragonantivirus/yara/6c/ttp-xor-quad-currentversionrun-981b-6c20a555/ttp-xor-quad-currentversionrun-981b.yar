rule TTP_XOR_QUAD_CurrentVersionRun_981b {
  strings:
    $key_981b = { cb 74 [2] ef 7a [2] c4 56 [2] ea 74 [2] fe 6f [2] f1 75 [2] ef 68 [2] ed 69 [2] f6 6f [2] ea 68 [2] f6 47 }

  condition:
    any of them
}