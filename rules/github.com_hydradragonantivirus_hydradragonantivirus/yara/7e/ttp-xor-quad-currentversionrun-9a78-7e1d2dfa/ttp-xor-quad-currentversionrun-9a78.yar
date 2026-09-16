rule TTP_XOR_QUAD_CurrentVersionRun_9a78 {
  strings:
    $key_9a78 = { c9 17 [2] ed 19 [2] c6 35 [2] e8 17 [2] fc 0c [2] f3 16 [2] ed 0b [2] ef 0a [2] f4 0c [2] e8 0b [2] f4 24 }

  condition:
    any of them
}