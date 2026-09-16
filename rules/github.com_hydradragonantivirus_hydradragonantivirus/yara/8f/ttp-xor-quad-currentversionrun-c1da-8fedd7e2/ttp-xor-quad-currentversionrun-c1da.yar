rule TTP_XOR_QUAD_CurrentVersionRun_c1da {
  strings:
    $key_c1da = { 92 b5 [2] b6 bb [2] 9d 97 [2] b3 b5 [2] a7 ae [2] a8 b4 [2] b6 a9 [2] b4 a8 [2] af ae [2] b3 a9 [2] af 86 }

  condition:
    any of them
}