rule TTP_XOR_QUAD_CurrentVersionRun_d1db {
  strings:
    $key_d1db = { 82 b4 [2] a6 ba [2] 8d 96 [2] a3 b4 [2] b7 af [2] b8 b5 [2] a6 a8 [2] a4 a9 [2] bf af [2] a3 a8 [2] bf 87 }

  condition:
    any of them
}