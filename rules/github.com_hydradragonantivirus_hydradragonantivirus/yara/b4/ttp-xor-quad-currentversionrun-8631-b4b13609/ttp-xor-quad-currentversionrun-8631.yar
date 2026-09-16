rule TTP_XOR_QUAD_CurrentVersionRun_8631 {
  strings:
    $key_8631 = { d5 5e [2] f1 50 [2] da 7c [2] f4 5e [2] e0 45 [2] ef 5f [2] f1 42 [2] f3 43 [2] e8 45 [2] f4 42 [2] e8 6d }

  condition:
    any of them
}