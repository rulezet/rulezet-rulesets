rule TTP_XOR_QUAD_CurrentVersionRun_9a77 {
  strings:
    $key_9a77 = { c9 18 [2] ed 16 [2] c6 3a [2] e8 18 [2] fc 03 [2] f3 19 [2] ed 04 [2] ef 05 [2] f4 03 [2] e8 04 [2] f4 2b }

  condition:
    any of them
}