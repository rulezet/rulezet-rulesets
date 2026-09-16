rule TTP_XOR_QUAD_CurrentVersionRun_9aeb {
  strings:
    $key_9aeb = { c9 84 [2] ed 8a [2] c6 a6 [2] e8 84 [2] fc 9f [2] f3 85 [2] ed 98 [2] ef 99 [2] f4 9f [2] e8 98 [2] f4 b7 }

  condition:
    any of them
}