rule TTP_XOR_QUAD_CurrentVersionRun_9479 {
  strings:
    $key_9479 = { c7 16 [2] e3 18 [2] c8 34 [2] e6 16 [2] f2 0d [2] fd 17 [2] e3 0a [2] e1 0b [2] fa 0d [2] e6 0a [2] fa 25 }

  condition:
    any of them
}