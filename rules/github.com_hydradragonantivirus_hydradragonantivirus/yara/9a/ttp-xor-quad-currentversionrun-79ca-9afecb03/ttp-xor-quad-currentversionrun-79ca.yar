rule TTP_XOR_QUAD_CurrentVersionRun_79ca {
  strings:
    $key_79ca = { 2a a5 [2] 0e ab [2] 25 87 [2] 0b a5 [2] 1f be [2] 10 a4 [2] 0e b9 [2] 0c b8 [2] 17 be [2] 0b b9 [2] 17 96 }

  condition:
    any of them
}