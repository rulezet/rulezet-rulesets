rule TTP_XOR_QUAD_CurrentVersionRun_9a42 {
  strings:
    $key_9a42 = { c9 2d [2] ed 23 [2] c6 0f [2] e8 2d [2] fc 36 [2] f3 2c [2] ed 31 [2] ef 30 [2] f4 36 [2] e8 31 [2] f4 1e }

  condition:
    any of them
}