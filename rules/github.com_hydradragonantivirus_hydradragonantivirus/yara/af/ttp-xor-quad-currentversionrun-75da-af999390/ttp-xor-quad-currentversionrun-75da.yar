rule TTP_XOR_QUAD_CurrentVersionRun_75da {
  strings:
    $key_75da = { 26 b5 [2] 02 bb [2] 29 97 [2] 07 b5 [2] 13 ae [2] 1c b4 [2] 02 a9 [2] 00 a8 [2] 1b ae [2] 07 a9 [2] 1b 86 }

  condition:
    any of them
}