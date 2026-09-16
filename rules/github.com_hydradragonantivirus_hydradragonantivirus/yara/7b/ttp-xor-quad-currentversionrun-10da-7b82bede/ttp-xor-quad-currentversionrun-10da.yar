rule TTP_XOR_QUAD_CurrentVersionRun_10da {
  strings:
    $key_10da = { 43 b5 [2] 67 bb [2] 4c 97 [2] 62 b5 [2] 76 ae [2] 79 b4 [2] 67 a9 [2] 65 a8 [2] 7e ae [2] 62 a9 [2] 7e 86 }

  condition:
    any of them
}