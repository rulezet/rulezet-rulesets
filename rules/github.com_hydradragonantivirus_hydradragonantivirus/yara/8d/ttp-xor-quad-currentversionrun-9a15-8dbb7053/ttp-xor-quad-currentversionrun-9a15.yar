rule TTP_XOR_QUAD_CurrentVersionRun_9a15 {
  strings:
    $key_9a15 = { c9 7a [2] ed 74 [2] c6 58 [2] e8 7a [2] fc 61 [2] f3 7b [2] ed 66 [2] ef 67 [2] f4 61 [2] e8 66 [2] f4 49 }

  condition:
    any of them
}