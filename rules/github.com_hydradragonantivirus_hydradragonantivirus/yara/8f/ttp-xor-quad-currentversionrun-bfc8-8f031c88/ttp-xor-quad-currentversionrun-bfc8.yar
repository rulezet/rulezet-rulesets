rule TTP_XOR_QUAD_CurrentVersionRun_bfc8 {
  strings:
    $key_bfc8 = { ec a7 [2] c8 a9 [2] e3 85 [2] cd a7 [2] d9 bc [2] d6 a6 [2] c8 bb [2] ca ba [2] d1 bc [2] cd bb [2] d1 94 }

  condition:
    any of them
}