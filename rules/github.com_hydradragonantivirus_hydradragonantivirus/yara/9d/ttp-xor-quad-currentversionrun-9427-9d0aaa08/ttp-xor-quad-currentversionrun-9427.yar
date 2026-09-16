rule TTP_XOR_QUAD_CurrentVersionRun_9427 {
  strings:
    $key_9427 = { c7 48 [2] e3 46 [2] c8 6a [2] e6 48 [2] f2 53 [2] fd 49 [2] e3 54 [2] e1 55 [2] fa 53 [2] e6 54 [2] fa 7b }

  condition:
    any of them
}