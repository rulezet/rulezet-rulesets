rule TTP_XOR_QUAD_CurrentVersionRun_981c {
  strings:
    $key_981c = { cb 73 [2] ef 7d [2] c4 51 [2] ea 73 [2] fe 68 [2] f1 72 [2] ef 6f [2] ed 6e [2] f6 68 [2] ea 6f [2] f6 40 }

  condition:
    any of them
}