rule TTP_XOR_QUAD_CurrentVersionRun_9a26 {
  strings:
    $key_9a26 = { c9 49 [2] ed 47 [2] c6 6b [2] e8 49 [2] fc 52 [2] f3 48 [2] ed 55 [2] ef 54 [2] f4 52 [2] e8 55 [2] f4 7a }

  condition:
    any of them
}