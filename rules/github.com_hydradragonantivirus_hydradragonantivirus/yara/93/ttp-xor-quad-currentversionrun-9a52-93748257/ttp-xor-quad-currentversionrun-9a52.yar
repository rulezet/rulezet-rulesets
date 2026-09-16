rule TTP_XOR_QUAD_CurrentVersionRun_9a52 {
  strings:
    $key_9a52 = { c9 3d [2] ed 33 [2] c6 1f [2] e8 3d [2] fc 26 [2] f3 3c [2] ed 21 [2] ef 20 [2] f4 26 [2] e8 21 [2] f4 0e }

  condition:
    any of them
}