rule TTP_XOR_QUAD_CurrentVersionRun_e7da {
  strings:
    $key_e7da = { b4 b5 [2] 90 bb [2] bb 97 [2] 95 b5 [2] 81 ae [2] 8e b4 [2] 90 a9 [2] 92 a8 [2] 89 ae [2] 95 a9 [2] 89 86 }

  condition:
    any of them
}