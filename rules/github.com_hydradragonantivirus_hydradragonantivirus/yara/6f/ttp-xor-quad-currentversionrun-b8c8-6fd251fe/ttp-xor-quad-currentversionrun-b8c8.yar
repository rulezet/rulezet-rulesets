rule TTP_XOR_QUAD_CurrentVersionRun_b8c8 {
  strings:
    $key_b8c8 = { eb a7 [2] cf a9 [2] e4 85 [2] ca a7 [2] de bc [2] d1 a6 [2] cf bb [2] cd ba [2] d6 bc [2] ca bb [2] d6 94 }

  condition:
    any of them
}