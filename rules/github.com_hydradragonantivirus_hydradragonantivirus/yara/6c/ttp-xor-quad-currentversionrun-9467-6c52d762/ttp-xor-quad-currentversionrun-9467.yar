rule TTP_XOR_QUAD_CurrentVersionRun_9467 {
  strings:
    $key_9467 = { c7 08 [2] e3 06 [2] c8 2a [2] e6 08 [2] f2 13 [2] fd 09 [2] e3 14 [2] e1 15 [2] fa 13 [2] e6 14 [2] fa 3b }

  condition:
    any of them
}