rule TTP_XOR_QUAD_CurrentVersionRun_91c7 {
  strings:
    $key_91c7 = { c2 a8 [2] e6 a6 [2] cd 8a [2] e3 a8 [2] f7 b3 [2] f8 a9 [2] e6 b4 [2] e4 b5 [2] ff b3 [2] e3 b4 [2] ff 9b }

  condition:
    any of them
}