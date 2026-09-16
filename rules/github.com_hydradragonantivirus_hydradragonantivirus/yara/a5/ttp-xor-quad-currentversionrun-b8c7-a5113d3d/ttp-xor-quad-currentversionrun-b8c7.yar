rule TTP_XOR_QUAD_CurrentVersionRun_b8c7 {
  strings:
    $key_b8c7 = { eb a8 [2] cf a6 [2] e4 8a [2] ca a8 [2] de b3 [2] d1 a9 [2] cf b4 [2] cd b5 [2] d6 b3 [2] ca b4 [2] d6 9b }

  condition:
    any of them
}