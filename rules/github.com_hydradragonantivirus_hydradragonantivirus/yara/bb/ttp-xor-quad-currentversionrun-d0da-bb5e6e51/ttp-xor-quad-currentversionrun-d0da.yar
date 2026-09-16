rule TTP_XOR_QUAD_CurrentVersionRun_d0da {
  strings:
    $key_d0da = { 83 b5 [2] a7 bb [2] 8c 97 [2] a2 b5 [2] b6 ae [2] b9 b4 [2] a7 a9 [2] a5 a8 [2] be ae [2] a2 a9 [2] be 86 }

  condition:
    any of them
}