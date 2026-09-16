rule TTP_XOR_QUAD_CurrentVersionRun_f9d7 {
  strings:
    $key_f9d7 = { aa b8 [2] 8e b6 [2] a5 9a [2] 8b b8 [2] 9f a3 [2] 90 b9 [2] 8e a4 [2] 8c a5 [2] 97 a3 [2] 8b a4 [2] 97 8b }

  condition:
    any of them
}