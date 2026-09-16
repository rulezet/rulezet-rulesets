rule TTP_XOR_QUAD_CurrentVersionRun_9822 {
  strings:
    $key_9822 = { cb 4d [2] ef 43 [2] c4 6f [2] ea 4d [2] fe 56 [2] f1 4c [2] ef 51 [2] ed 50 [2] f6 56 [2] ea 51 [2] f6 7e }

  condition:
    any of them
}