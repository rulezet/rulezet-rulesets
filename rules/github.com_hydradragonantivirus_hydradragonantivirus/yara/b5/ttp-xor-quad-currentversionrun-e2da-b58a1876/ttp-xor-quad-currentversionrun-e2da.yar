rule TTP_XOR_QUAD_CurrentVersionRun_e2da {
  strings:
    $key_e2da = { b1 b5 [2] 95 bb [2] be 97 [2] 90 b5 [2] 84 ae [2] 8b b4 [2] 95 a9 [2] 97 a8 [2] 8c ae [2] 90 a9 [2] 8c 86 }

  condition:
    any of them
}