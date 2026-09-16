rule TTP_XOR_QUAD_CurrentVersionRun_d0db {
  strings:
    $key_d0db = { 83 b4 [2] a7 ba [2] 8c 96 [2] a2 b4 [2] b6 af [2] b9 b5 [2] a7 a8 [2] a5 a9 [2] be af [2] a2 a8 [2] be 87 }

  condition:
    any of them
}