rule TTP_XOR_QUAD_CurrentVersionRun_91d6 {
  strings:
    $key_91d6 = { c2 b9 [2] e6 b7 [2] cd 9b [2] e3 b9 [2] f7 a2 [2] f8 b8 [2] e6 a5 [2] e4 a4 [2] ff a2 [2] e3 a5 [2] ff 8a }

  condition:
    any of them
}