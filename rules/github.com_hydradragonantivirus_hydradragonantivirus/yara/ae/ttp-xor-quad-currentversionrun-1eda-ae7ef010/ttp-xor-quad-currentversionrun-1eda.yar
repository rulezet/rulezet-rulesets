rule TTP_XOR_QUAD_CurrentVersionRun_1eda {
  strings:
    $key_1eda = { 4d b5 [2] 69 bb [2] 42 97 [2] 6c b5 [2] 78 ae [2] 77 b4 [2] 69 a9 [2] 6b a8 [2] 70 ae [2] 6c a9 [2] 70 86 }

  condition:
    any of them
}