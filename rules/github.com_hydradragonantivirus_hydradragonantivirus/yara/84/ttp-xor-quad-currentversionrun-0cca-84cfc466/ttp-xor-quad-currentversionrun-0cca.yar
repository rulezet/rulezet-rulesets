rule TTP_XOR_QUAD_CurrentVersionRun_0cca {
  strings:
    $key_0cca = { 5f a5 [2] 7b ab [2] 50 87 [2] 7e a5 [2] 6a be [2] 65 a4 [2] 7b b9 [2] 79 b8 [2] 62 be [2] 7e b9 [2] 62 96 }

  condition:
    any of them
}