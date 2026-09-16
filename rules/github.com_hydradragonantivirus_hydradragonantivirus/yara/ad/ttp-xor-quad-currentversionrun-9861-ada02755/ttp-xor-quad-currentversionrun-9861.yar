rule TTP_XOR_QUAD_CurrentVersionRun_9861 {
  strings:
    $key_9861 = { cb 0e [2] ef 00 [2] c4 2c [2] ea 0e [2] fe 15 [2] f1 0f [2] ef 12 [2] ed 13 [2] f6 15 [2] ea 12 [2] f6 3d }

  condition:
    any of them
}