rule TTP_XOR_QUAD_CurrentVersionRun_a396 {
  strings:
    $key_a396 = { f0 f9 [2] d4 f7 [2] ff db [2] d1 f9 [2] c5 e2 [2] ca f8 [2] d4 e5 [2] d6 e4 [2] cd e2 [2] d1 e5 [2] cd ca }

  condition:
    any of them
}