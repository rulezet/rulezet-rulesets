rule TTP_XOR_QUAD_CurrentVersionRun_a3a4 {
  strings:
    $key_a3a4 = { f0 cb [2] d4 c5 [2] ff e9 [2] d1 cb [2] c5 d0 [2] ca ca [2] d4 d7 [2] d6 d6 [2] cd d0 [2] d1 d7 [2] cd f8 }

  condition:
    any of them
}