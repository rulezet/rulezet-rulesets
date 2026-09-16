rule TTP_XOR_QUAD_CurrentVersionRun_7eda {
  strings:
    $key_7eda = { 2d b5 [2] 09 bb [2] 22 97 [2] 0c b5 [2] 18 ae [2] 17 b4 [2] 09 a9 [2] 0b a8 [2] 10 ae [2] 0c a9 [2] 10 86 }

  condition:
    any of them
}