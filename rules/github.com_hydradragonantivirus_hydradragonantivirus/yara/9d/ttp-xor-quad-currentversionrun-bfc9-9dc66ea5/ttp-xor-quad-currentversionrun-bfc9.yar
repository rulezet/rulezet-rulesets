rule TTP_XOR_QUAD_CurrentVersionRun_bfc9 {
  strings:
    $key_bfc9 = { ec a6 [2] c8 a8 [2] e3 84 [2] cd a6 [2] d9 bd [2] d6 a7 [2] c8 ba [2] ca bb [2] d1 bd [2] cd ba [2] d1 95 }

  condition:
    any of them
}