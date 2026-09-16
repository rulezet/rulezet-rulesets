rule TTP_XOR_QUAD_CurrentVersionRun_3cca {
  strings:
    $key_3cca = { 6f a5 [2] 4b ab [2] 60 87 [2] 4e a5 [2] 5a be [2] 55 a4 [2] 4b b9 [2] 49 b8 [2] 52 be [2] 4e b9 [2] 52 96 }

  condition:
    any of them
}