rule TTP_XOR_QUAD_CurrentVersionRun_9477 {
  strings:
    $key_9477 = { c7 18 [2] e3 16 [2] c8 3a [2] e6 18 [2] f2 03 [2] fd 19 [2] e3 04 [2] e1 05 [2] fa 03 [2] e6 04 [2] fa 2b }

  condition:
    any of them
}