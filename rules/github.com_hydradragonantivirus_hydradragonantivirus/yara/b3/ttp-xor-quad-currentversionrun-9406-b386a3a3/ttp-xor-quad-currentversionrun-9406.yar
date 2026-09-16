rule TTP_XOR_QUAD_CurrentVersionRun_9406 {
  strings:
    $key_9406 = { c7 69 [2] e3 67 [2] c8 4b [2] e6 69 [2] f2 72 [2] fd 68 [2] e3 75 [2] e1 74 [2] fa 72 [2] e6 75 [2] fa 5a }

  condition:
    any of them
}