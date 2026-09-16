rule TTP_XOR_QUAD_CurrentVersionRun_9457 {
  strings:
    $key_9457 = { c7 38 [2] e3 36 [2] c8 1a [2] e6 38 [2] f2 23 [2] fd 39 [2] e3 24 [2] e1 25 [2] fa 23 [2] e6 24 [2] fa 0b }

  condition:
    any of them
}