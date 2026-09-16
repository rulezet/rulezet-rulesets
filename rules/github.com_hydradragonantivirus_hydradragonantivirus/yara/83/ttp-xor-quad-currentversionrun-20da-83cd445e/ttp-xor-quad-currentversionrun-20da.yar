rule TTP_XOR_QUAD_CurrentVersionRun_20da {
  strings:
    $key_20da = { 73 b5 [2] 57 bb [2] 7c 97 [2] 52 b5 [2] 46 ae [2] 49 b4 [2] 57 a9 [2] 55 a8 [2] 4e ae [2] 52 a9 [2] 4e 86 }

  condition:
    any of them
}