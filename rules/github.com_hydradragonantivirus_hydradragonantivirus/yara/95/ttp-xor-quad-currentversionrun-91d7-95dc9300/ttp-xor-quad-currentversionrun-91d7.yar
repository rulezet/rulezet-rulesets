rule TTP_XOR_QUAD_CurrentVersionRun_91d7 {
  strings:
    $key_91d7 = { c2 b8 [2] e6 b6 [2] cd 9a [2] e3 b8 [2] f7 a3 [2] f8 b9 [2] e6 a4 [2] e4 a5 [2] ff a3 [2] e3 a4 [2] ff 8b }

  condition:
    any of them
}