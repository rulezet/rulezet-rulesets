rule TTP_XOR_QUAD_CurrentVersionRun_9a74 {
  strings:
    $key_9a74 = { c9 1b [2] ed 15 [2] c6 39 [2] e8 1b [2] fc 00 [2] f3 1a [2] ed 07 [2] ef 06 [2] f4 00 [2] e8 07 [2] f4 28 }

  condition:
    any of them
}