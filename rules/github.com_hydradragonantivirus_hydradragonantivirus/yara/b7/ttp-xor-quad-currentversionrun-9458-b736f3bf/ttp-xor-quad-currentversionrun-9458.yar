rule TTP_XOR_QUAD_CurrentVersionRun_9458 {
  strings:
    $key_9458 = { c7 37 [2] e3 39 [2] c8 15 [2] e6 37 [2] f2 2c [2] fd 36 [2] e3 2b [2] e1 2a [2] fa 2c [2] e6 2b [2] fa 04 }

  condition:
    any of them
}