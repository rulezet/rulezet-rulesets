rule TTP_XOR_QUAD_CurrentVersionRun_981d {
  strings:
    $key_981d = { cb 72 [2] ef 7c [2] c4 50 [2] ea 72 [2] fe 69 [2] f1 73 [2] ef 6e [2] ed 6f [2] f6 69 [2] ea 6e [2] f6 41 }

  condition:
    any of them
}