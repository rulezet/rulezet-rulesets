rule TTP_XOR_QUAD_CurrentVersionRun_98ec {
  strings:
    $key_98ec = { cb 83 [2] ef 8d [2] c4 a1 [2] ea 83 [2] fe 98 [2] f1 82 [2] ef 9f [2] ed 9e [2] f6 98 [2] ea 9f [2] f6 b0 }

  condition:
    any of them
}