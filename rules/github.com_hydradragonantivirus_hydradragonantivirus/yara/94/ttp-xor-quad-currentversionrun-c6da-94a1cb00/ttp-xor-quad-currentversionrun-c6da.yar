rule TTP_XOR_QUAD_CurrentVersionRun_c6da {
  strings:
    $key_c6da = { 95 b5 [2] b1 bb [2] 9a 97 [2] b4 b5 [2] a0 ae [2] af b4 [2] b1 a9 [2] b3 a8 [2] a8 ae [2] b4 a9 [2] a8 86 }

  condition:
    any of them
}