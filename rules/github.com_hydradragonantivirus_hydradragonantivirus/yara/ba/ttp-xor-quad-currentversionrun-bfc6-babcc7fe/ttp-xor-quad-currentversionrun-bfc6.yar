rule TTP_XOR_QUAD_CurrentVersionRun_bfc6 {
  strings:
    $key_bfc6 = { ec a9 [2] c8 a7 [2] e3 8b [2] cd a9 [2] d9 b2 [2] d6 a8 [2] c8 b5 [2] ca b4 [2] d1 b2 [2] cd b5 [2] d1 9a }

  condition:
    any of them
}