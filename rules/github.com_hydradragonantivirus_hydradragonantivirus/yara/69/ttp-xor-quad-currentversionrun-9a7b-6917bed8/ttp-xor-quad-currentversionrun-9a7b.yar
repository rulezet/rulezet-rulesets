rule TTP_XOR_QUAD_CurrentVersionRun_9a7b {
  strings:
    $key_9a7b = { c9 14 [2] ed 1a [2] c6 36 [2] e8 14 [2] fc 0f [2] f3 15 [2] ed 08 [2] ef 09 [2] f4 0f [2] e8 08 [2] f4 27 }

  condition:
    any of them
}