rule TTP_XOR_QUAD_CurrentVersionRun_05da {
  strings:
    $key_05da = { 56 b5 [2] 72 bb [2] 59 97 [2] 77 b5 [2] 63 ae [2] 6c b4 [2] 72 a9 [2] 70 a8 [2] 6b ae [2] 77 a9 [2] 6b 86 }

  condition:
    any of them
}