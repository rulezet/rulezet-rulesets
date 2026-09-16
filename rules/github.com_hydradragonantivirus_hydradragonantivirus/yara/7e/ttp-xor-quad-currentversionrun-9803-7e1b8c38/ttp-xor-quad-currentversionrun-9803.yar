rule TTP_XOR_QUAD_CurrentVersionRun_9803 {
  strings:
    $key_9803 = { cb 6c [2] ef 62 [2] c4 4e [2] ea 6c [2] fe 77 [2] f1 6d [2] ef 70 [2] ed 71 [2] f6 77 [2] ea 70 [2] f6 5f }

  condition:
    any of them
}