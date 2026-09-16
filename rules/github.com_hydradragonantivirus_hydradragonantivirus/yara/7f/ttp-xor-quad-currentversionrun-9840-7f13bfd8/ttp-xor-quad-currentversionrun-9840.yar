rule TTP_XOR_QUAD_CurrentVersionRun_9840 {
  strings:
    $key_9840 = { cb 2f [2] ef 21 [2] c4 0d [2] ea 2f [2] fe 34 [2] f1 2e [2] ef 33 [2] ed 32 [2] f6 34 [2] ea 33 [2] f6 1c }

  condition:
    any of them
}