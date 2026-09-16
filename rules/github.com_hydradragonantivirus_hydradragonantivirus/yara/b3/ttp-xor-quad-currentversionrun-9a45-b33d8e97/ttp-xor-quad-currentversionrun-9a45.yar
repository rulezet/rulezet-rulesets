rule TTP_XOR_QUAD_CurrentVersionRun_9a45 {
  strings:
    $key_9a45 = { c9 2a [2] ed 24 [2] c6 08 [2] e8 2a [2] fc 31 [2] f3 2b [2] ed 36 [2] ef 37 [2] f4 31 [2] e8 36 [2] f4 19 }

  condition:
    any of them
}