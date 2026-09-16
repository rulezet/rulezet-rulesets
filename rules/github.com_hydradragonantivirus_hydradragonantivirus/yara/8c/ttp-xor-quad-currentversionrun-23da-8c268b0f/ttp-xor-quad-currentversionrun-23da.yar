rule TTP_XOR_QUAD_CurrentVersionRun_23da {
  strings:
    $key_23da = { 70 b5 [2] 54 bb [2] 7f 97 [2] 51 b5 [2] 45 ae [2] 4a b4 [2] 54 a9 [2] 56 a8 [2] 4d ae [2] 51 a9 [2] 4d 86 }

  condition:
    any of them
}