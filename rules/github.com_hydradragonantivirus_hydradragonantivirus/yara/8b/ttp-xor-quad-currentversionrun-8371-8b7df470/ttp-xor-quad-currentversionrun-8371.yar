rule TTP_XOR_QUAD_CurrentVersionRun_8371 {
  strings:
    $key_8371 = { d0 1e [2] f4 10 [2] df 3c [2] f1 1e [2] e5 05 [2] ea 1f [2] f4 02 [2] f6 03 [2] ed 05 [2] f1 02 [2] ed 2d }

  condition:
    any of them
}