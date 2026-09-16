rule TTP_XOR_QUAD_CurrentVersionRun_63da {
  strings:
    $key_63da = { 30 b5 [2] 14 bb [2] 3f 97 [2] 11 b5 [2] 05 ae [2] 0a b4 [2] 14 a9 [2] 16 a8 [2] 0d ae [2] 11 a9 [2] 0d 86 }

  condition:
    any of them
}