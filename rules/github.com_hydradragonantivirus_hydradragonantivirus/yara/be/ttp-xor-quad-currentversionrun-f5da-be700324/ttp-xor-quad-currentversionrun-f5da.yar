rule TTP_XOR_QUAD_CurrentVersionRun_f5da {
  strings:
    $key_f5da = { a6 b5 [2] 82 bb [2] a9 97 [2] 87 b5 [2] 93 ae [2] 9c b4 [2] 82 a9 [2] 80 a8 [2] 9b ae [2] 87 a9 [2] 9b 86 }

  condition:
    any of them
}