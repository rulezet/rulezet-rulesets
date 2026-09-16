rule TTP_XOR_QUAD_CurrentVersionRun_9a27 {
  strings:
    $key_9a27 = { c9 48 [2] ed 46 [2] c6 6a [2] e8 48 [2] fc 53 [2] f3 49 [2] ed 54 [2] ef 55 [2] f4 53 [2] e8 54 [2] f4 7b }

  condition:
    any of them
}