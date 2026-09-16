rule TTP_XOR_QUAD_CurrentVersionRun_9850 {
  strings:
    $key_9850 = { cb 3f [2] ef 31 [2] c4 1d [2] ea 3f [2] fe 24 [2] f1 3e [2] ef 23 [2] ed 22 [2] f6 24 [2] ea 23 [2] f6 0c }

  condition:
    any of them
}