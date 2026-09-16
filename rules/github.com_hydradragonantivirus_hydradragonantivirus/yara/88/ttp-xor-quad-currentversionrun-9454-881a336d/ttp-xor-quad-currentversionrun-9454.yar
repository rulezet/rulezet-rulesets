rule TTP_XOR_QUAD_CurrentVersionRun_9454 {
  strings:
    $key_9454 = { c7 3b [2] e3 35 [2] c8 19 [2] e6 3b [2] f2 20 [2] fd 3a [2] e3 27 [2] e1 26 [2] fa 20 [2] e6 27 [2] fa 08 }

  condition:
    any of them
}