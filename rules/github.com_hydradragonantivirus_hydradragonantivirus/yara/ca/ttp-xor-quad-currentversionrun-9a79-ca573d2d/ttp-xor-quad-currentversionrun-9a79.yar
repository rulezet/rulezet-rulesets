rule TTP_XOR_QUAD_CurrentVersionRun_9a79 {
  strings:
    $key_9a79 = { c9 16 [2] ed 18 [2] c6 34 [2] e8 16 [2] fc 0d [2] f3 17 [2] ed 0a [2] ef 0b [2] f4 0d [2] e8 0a [2] f4 25 }

  condition:
    any of them
}