rule TTP_XOR_QUAD_CurrentVersionRun_70da {
  strings:
    $key_70da = { 23 b5 [2] 07 bb [2] 2c 97 [2] 02 b5 [2] 16 ae [2] 19 b4 [2] 07 a9 [2] 05 a8 [2] 1e ae [2] 02 a9 [2] 1e 86 }

  condition:
    any of them
}