rule TTP_XOR_QUAD_CurrentVersionRun_f9c7 {
  strings:
    $key_f9c7 = { aa a8 [2] 8e a6 [2] a5 8a [2] 8b a8 [2] 9f b3 [2] 90 a9 [2] 8e b4 [2] 8c b5 [2] 97 b3 [2] 8b b4 [2] 97 9b }

  condition:
    any of them
}