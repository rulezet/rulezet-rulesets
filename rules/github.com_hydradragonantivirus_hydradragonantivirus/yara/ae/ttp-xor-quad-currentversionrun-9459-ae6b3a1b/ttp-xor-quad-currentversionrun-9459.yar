rule TTP_XOR_QUAD_CurrentVersionRun_9459 {
  strings:
    $key_9459 = { c7 36 [2] e3 38 [2] c8 14 [2] e6 36 [2] f2 2d [2] fd 37 [2] e3 2a [2] e1 2b [2] fa 2d [2] e6 2a [2] fa 05 }

  condition:
    any of them
}