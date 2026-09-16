rule TTP_XOR_QUAD_CurrentVersionRun_a3d7 {
  strings:
    $key_a3d7 = { f0 b8 [2] d4 b6 [2] ff 9a [2] d1 b8 [2] c5 a3 [2] ca b9 [2] d4 a4 [2] d6 a5 [2] cd a3 [2] d1 a4 [2] cd 8b }

  condition:
    any of them
}