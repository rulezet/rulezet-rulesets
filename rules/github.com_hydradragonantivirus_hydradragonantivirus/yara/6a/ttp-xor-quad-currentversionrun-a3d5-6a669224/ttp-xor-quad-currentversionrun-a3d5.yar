rule TTP_XOR_QUAD_CurrentVersionRun_a3d5 {
  strings:
    $key_a3d5 = { f0 ba [2] d4 b4 [2] ff 98 [2] d1 ba [2] c5 a1 [2] ca bb [2] d4 a6 [2] d6 a7 [2] cd a1 [2] d1 a6 [2] cd 89 }

  condition:
    any of them
}