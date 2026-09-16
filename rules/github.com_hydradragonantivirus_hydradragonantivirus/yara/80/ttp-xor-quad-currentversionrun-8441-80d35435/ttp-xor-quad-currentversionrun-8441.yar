rule TTP_XOR_QUAD_CurrentVersionRun_8441 {
  strings:
    $key_8441 = { d7 2e [2] f3 20 [2] d8 0c [2] f6 2e [2] e2 35 [2] ed 2f [2] f3 32 [2] f1 33 [2] ea 35 [2] f6 32 [2] ea 1d }

  condition:
    any of them
}