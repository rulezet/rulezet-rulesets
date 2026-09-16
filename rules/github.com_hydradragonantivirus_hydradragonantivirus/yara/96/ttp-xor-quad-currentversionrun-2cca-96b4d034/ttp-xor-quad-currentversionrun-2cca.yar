rule TTP_XOR_QUAD_CurrentVersionRun_2cca {
  strings:
    $key_2cca = { 7f a5 [2] 5b ab [2] 70 87 [2] 5e a5 [2] 4a be [2] 45 a4 [2] 5b b9 [2] 59 b8 [2] 42 be [2] 5e b9 [2] 42 96 }

  condition:
    any of them
}