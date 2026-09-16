rule TTP_XOR_QUAD_CurrentVersionRun_8641 {
  strings:
    $key_8641 = { d5 2e [2] f1 20 [2] da 0c [2] f4 2e [2] e0 35 [2] ef 2f [2] f1 32 [2] f3 33 [2] e8 35 [2] f4 32 [2] e8 1d }

  condition:
    any of them
}