rule TTP_XOR_QUAD_CurrentVersionRun_a3e6 {
  strings:
    $key_a3e6 = { f0 89 [2] d4 87 [2] ff ab [2] d1 89 [2] c5 92 [2] ca 88 [2] d4 95 [2] d6 94 [2] cd 92 [2] d1 95 [2] cd ba }

  condition:
    any of them
}