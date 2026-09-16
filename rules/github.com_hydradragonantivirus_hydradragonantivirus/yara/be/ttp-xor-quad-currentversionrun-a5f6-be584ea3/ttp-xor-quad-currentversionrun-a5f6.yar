rule TTP_XOR_QUAD_CurrentVersionRun_a5f6 {
  strings:
    $key_a5f6 = { f6 99 [2] d2 97 [2] f9 bb [2] d7 99 [2] c3 82 [2] cc 98 [2] d2 85 [2] d0 84 [2] cb 82 [2] d7 85 [2] cb aa }

  condition:
    any of them
}