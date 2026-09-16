rule TTP_XOR_QUAD_CurrentVersionRun_9447 {
  strings:
    $key_9447 = { c7 28 [2] e3 26 [2] c8 0a [2] e6 28 [2] f2 33 [2] fd 29 [2] e3 34 [2] e1 35 [2] fa 33 [2] e6 34 [2] fa 1b }

  condition:
    any of them
}