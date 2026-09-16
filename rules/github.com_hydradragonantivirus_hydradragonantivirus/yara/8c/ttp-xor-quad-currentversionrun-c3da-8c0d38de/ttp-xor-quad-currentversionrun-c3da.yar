rule TTP_XOR_QUAD_CurrentVersionRun_c3da {
  strings:
    $key_c3da = { 90 b5 [2] b4 bb [2] 9f 97 [2] b1 b5 [2] a5 ae [2] aa b4 [2] b4 a9 [2] b6 a8 [2] ad ae [2] b1 a9 [2] ad 86 }

  condition:
    any of them
}