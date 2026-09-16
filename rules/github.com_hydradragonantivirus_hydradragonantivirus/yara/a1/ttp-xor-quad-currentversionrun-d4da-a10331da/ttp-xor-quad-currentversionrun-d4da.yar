rule TTP_XOR_QUAD_CurrentVersionRun_d4da {
  strings:
    $key_d4da = { 87 b5 [2] a3 bb [2] 88 97 [2] a6 b5 [2] b2 ae [2] bd b4 [2] a3 a9 [2] a1 a8 [2] ba ae [2] a6 a9 [2] ba 86 }

  condition:
    any of them
}