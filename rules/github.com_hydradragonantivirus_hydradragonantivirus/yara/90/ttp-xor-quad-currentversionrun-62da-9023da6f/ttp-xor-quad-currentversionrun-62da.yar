rule TTP_XOR_QUAD_CurrentVersionRun_62da {
  strings:
    $key_62da = { 31 b5 [2] 15 bb [2] 3e 97 [2] 10 b5 [2] 04 ae [2] 0b b4 [2] 15 a9 [2] 17 a8 [2] 0c ae [2] 10 a9 [2] 0c 86 }

  condition:
    any of them
}