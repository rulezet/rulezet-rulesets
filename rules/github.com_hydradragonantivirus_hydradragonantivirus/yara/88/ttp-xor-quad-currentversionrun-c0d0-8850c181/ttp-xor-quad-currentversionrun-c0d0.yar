rule TTP_XOR_QUAD_CurrentVersionRun_c0d0 {
  strings:
    $key_c0d0 = { 93 bf [2] b7 b1 [2] 9c 9d [2] b2 bf [2] a6 a4 [2] a9 be [2] b7 a3 [2] b5 a2 [2] ae a4 [2] b2 a3 [2] ae 8c }

  condition:
    any of them
}