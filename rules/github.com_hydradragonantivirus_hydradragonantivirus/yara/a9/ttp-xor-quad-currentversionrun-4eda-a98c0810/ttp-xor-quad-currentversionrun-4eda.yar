rule TTP_XOR_QUAD_CurrentVersionRun_4eda {
  strings:
    $key_4eda = { 1d b5 [2] 39 bb [2] 12 97 [2] 3c b5 [2] 28 ae [2] 27 b4 [2] 39 a9 [2] 3b a8 [2] 20 ae [2] 3c a9 [2] 20 86 }

  condition:
    any of them
}