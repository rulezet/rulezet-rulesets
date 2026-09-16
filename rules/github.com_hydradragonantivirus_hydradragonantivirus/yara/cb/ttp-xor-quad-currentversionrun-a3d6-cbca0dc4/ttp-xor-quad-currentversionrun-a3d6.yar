rule TTP_XOR_QUAD_CurrentVersionRun_a3d6 {
  strings:
    $key_a3d6 = { f0 b9 [2] d4 b7 [2] ff 9b [2] d1 b9 [2] c5 a2 [2] ca b8 [2] d4 a5 [2] d6 a4 [2] cd a2 [2] d1 a5 [2] cd 8a }

  condition:
    any of them
}