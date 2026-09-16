rule TTP_XOR_QUAD_CurrentVersionRun_9a59 {
  strings:
    $key_9a59 = { c9 36 [2] ed 38 [2] c6 14 [2] e8 36 [2] fc 2d [2] f3 37 [2] ed 2a [2] ef 2b [2] f4 2d [2] e8 2a [2] f4 05 }

  condition:
    any of them
}