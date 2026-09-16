rule TTP_XOR_QUAD_CurrentVersionRun_9830 {
  strings:
    $key_9830 = { cb 5f [2] ef 51 [2] c4 7d [2] ea 5f [2] fe 44 [2] f1 5e [2] ef 43 [2] ed 42 [2] f6 44 [2] ea 43 [2] f6 6c }

  condition:
    any of them
}