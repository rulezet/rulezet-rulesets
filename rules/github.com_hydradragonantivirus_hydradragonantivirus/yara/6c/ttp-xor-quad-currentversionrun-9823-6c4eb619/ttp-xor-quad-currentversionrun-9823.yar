rule TTP_XOR_QUAD_CurrentVersionRun_9823 {
  strings:
    $key_9823 = { cb 4c [2] ef 42 [2] c4 6e [2] ea 4c [2] fe 57 [2] f1 4d [2] ef 50 [2] ed 51 [2] f6 57 [2] ea 50 [2] f6 7f }

  condition:
    any of them
}