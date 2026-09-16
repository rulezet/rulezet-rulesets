rule TTP_XOR_QUAD_CurrentVersionRun_03da {
  strings:
    $key_03da = { 50 b5 [2] 74 bb [2] 5f 97 [2] 71 b5 [2] 65 ae [2] 6a b4 [2] 74 a9 [2] 76 a8 [2] 6d ae [2] 71 a9 [2] 6d 86 }

  condition:
    any of them
}