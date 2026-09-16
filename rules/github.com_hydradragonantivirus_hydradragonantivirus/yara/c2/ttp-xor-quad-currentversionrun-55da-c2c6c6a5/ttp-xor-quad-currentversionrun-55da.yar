rule TTP_XOR_QUAD_CurrentVersionRun_55da {
  strings:
    $key_55da = { 06 b5 [2] 22 bb [2] 09 97 [2] 27 b5 [2] 33 ae [2] 3c b4 [2] 22 a9 [2] 20 a8 [2] 3b ae [2] 27 a9 [2] 3b 86 }

  condition:
    any of them
}