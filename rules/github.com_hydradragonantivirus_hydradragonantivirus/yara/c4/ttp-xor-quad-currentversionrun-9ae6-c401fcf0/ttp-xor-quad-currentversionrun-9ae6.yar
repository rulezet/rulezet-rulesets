rule TTP_XOR_QUAD_CurrentVersionRun_9ae6 {
  strings:
    $key_9ae6 = { c9 89 [2] ed 87 [2] c6 ab [2] e8 89 [2] fc 92 [2] f3 88 [2] ed 95 [2] ef 94 [2] f4 92 [2] e8 95 [2] f4 ba }

  condition:
    any of them
}