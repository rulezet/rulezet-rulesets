rule TTP_XOR_QUAD_CurrentVersionRun_b8c6 {
  strings:
    $key_b8c6 = { eb a9 [2] cf a7 [2] e4 8b [2] ca a9 [2] de b2 [2] d1 a8 [2] cf b5 [2] cd b4 [2] d6 b2 [2] ca b5 [2] d6 9a }

  condition:
    any of them
}