rule TTP_XOR_QUAD_CurrentVersionRun_9464 {
  strings:
    $key_9464 = { c7 0b [2] e3 05 [2] c8 29 [2] e6 0b [2] f2 10 [2] fd 0a [2] e3 17 [2] e1 16 [2] fa 10 [2] e6 17 [2] fa 38 }

  condition:
    any of them
}