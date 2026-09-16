rule TTP_XOR_QUAD_CurrentVersionRun_9842 {
  strings:
    $key_9842 = { cb 2d [2] ef 23 [2] c4 0f [2] ea 2d [2] fe 36 [2] f1 2c [2] ef 31 [2] ed 30 [2] f6 36 [2] ea 31 [2] f6 1e }

  condition:
    any of them
}