rule TTP_XOR_QUAD_CurrentVersionRun_983b {
  strings:
    $key_983b = { cb 54 [2] ef 5a [2] c4 76 [2] ea 54 [2] fe 4f [2] f1 55 [2] ef 48 [2] ed 49 [2] f6 4f [2] ea 48 [2] f6 67 }

  condition:
    any of them
}