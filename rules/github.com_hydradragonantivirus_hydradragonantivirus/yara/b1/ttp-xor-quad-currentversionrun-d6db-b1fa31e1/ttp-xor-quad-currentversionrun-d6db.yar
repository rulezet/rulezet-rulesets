rule TTP_XOR_QUAD_CurrentVersionRun_d6db {
  strings:
    $key_d6db = { 85 b4 [2] a1 ba [2] 8a 96 [2] a4 b4 [2] b0 af [2] bf b5 [2] a1 a8 [2] a3 a9 [2] b8 af [2] a4 a8 [2] b8 87 }

  condition:
    any of them
}