rule TTP_XOR_QUAD_CurrentVersionRun_c7da {
  strings:
    $key_c7da = { 94 b5 [2] b0 bb [2] 9b 97 [2] b5 b5 [2] a1 ae [2] ae b4 [2] b0 a9 [2] b2 a8 [2] a9 ae [2] b5 a9 [2] a9 86 }

  condition:
    any of them
}