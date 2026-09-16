rule TTP_XOR_QUAD_CurrentVersionRun_9a22 {
  strings:
    $key_9a22 = { c9 4d [2] ed 43 [2] c6 6f [2] e8 4d [2] fc 56 [2] f3 4c [2] ed 51 [2] ef 50 [2] f4 56 [2] e8 51 [2] f4 7e }

  condition:
    any of them
}