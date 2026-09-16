rule TTP_XOR_QUAD_CurrentVersionRun_9a12 {
  strings:
    $key_9a12 = { c9 7d [2] ed 73 [2] c6 5f [2] e8 7d [2] fc 66 [2] f3 7c [2] ed 61 [2] ef 60 [2] f4 66 [2] e8 61 [2] f4 4e }

  condition:
    any of them
}