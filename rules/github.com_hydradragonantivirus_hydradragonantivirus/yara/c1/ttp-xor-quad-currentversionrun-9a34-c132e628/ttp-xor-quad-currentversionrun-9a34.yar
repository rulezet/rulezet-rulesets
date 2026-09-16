rule TTP_XOR_QUAD_CurrentVersionRun_9a34 {
  strings:
    $key_9a34 = { c9 5b [2] ed 55 [2] c6 79 [2] e8 5b [2] fc 40 [2] f3 5a [2] ed 47 [2] ef 46 [2] f4 40 [2] e8 47 [2] f4 68 }

  condition:
    any of them
}