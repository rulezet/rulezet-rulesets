rule TTP_XOR_QUAD_CurrentVersionRun_9456 {
  strings:
    $key_9456 = { c7 39 [2] e3 37 [2] c8 1b [2] e6 39 [2] f2 22 [2] fd 38 [2] e3 25 [2] e1 24 [2] fa 22 [2] e6 25 [2] fa 0a }

  condition:
    any of them
}