rule TTP_XOR_QUAD_CurrentVersionRun_b8d5 {
  strings:
    $key_b8d5 = { eb ba [2] cf b4 [2] e4 98 [2] ca ba [2] de a1 [2] d1 bb [2] cf a6 [2] cd a7 [2] d6 a1 [2] ca a6 [2] d6 89 }

  condition:
    any of them
}