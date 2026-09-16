rule TTP_XOR_QUAD_CurrentVersionRun_c7db {
  strings:
    $key_c7db = { 94 b4 [2] b0 ba [2] 9b 96 [2] b5 b4 [2] a1 af [2] ae b5 [2] b0 a8 [2] b2 a9 [2] a9 af [2] b5 a8 [2] a9 87 }

  condition:
    any of them
}