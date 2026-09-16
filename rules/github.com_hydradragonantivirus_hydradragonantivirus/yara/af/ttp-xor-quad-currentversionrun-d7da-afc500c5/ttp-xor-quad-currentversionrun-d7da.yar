rule TTP_XOR_QUAD_CurrentVersionRun_d7da {
  strings:
    $key_d7da = { 84 b5 [2] a0 bb [2] 8b 97 [2] a5 b5 [2] b1 ae [2] be b4 [2] a0 a9 [2] a2 a8 [2] b9 ae [2] a5 a9 [2] b9 86 }

  condition:
    any of them
}