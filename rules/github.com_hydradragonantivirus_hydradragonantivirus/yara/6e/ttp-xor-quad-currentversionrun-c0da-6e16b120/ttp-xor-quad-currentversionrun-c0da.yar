rule TTP_XOR_QUAD_CurrentVersionRun_c0da {
  strings:
    $key_c0da = { 93 b5 [2] b7 bb [2] 9c 97 [2] b2 b5 [2] a6 ae [2] a9 b4 [2] b7 a9 [2] b5 a8 [2] ae ae [2] b2 a9 [2] ae 86 }

  condition:
    any of them
}