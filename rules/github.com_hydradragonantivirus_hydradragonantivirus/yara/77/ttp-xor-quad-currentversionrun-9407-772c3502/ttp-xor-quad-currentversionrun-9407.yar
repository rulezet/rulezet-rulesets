rule TTP_XOR_QUAD_CurrentVersionRun_9407 {
  strings:
    $key_9407 = { c7 68 [2] e3 66 [2] c8 4a [2] e6 68 [2] f2 73 [2] fd 69 [2] e3 74 [2] e1 75 [2] fa 73 [2] e6 74 [2] fa 5b }

  condition:
    any of them
}