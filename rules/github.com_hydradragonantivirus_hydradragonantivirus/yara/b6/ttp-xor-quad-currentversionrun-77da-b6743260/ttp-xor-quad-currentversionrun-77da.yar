rule TTP_XOR_QUAD_CurrentVersionRun_77da {
  strings:
    $key_77da = { 24 b5 [2] 00 bb [2] 2b 97 [2] 05 b5 [2] 11 ae [2] 1e b4 [2] 00 a9 [2] 02 a8 [2] 19 ae [2] 05 a9 [2] 19 86 }

  condition:
    any of them
}