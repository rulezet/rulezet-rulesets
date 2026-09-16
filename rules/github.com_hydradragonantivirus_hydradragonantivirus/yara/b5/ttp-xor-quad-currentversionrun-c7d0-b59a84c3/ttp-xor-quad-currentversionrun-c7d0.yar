rule TTP_XOR_QUAD_CurrentVersionRun_c7d0 {
  strings:
    $key_c7d0 = { 94 bf [2] b0 b1 [2] 9b 9d [2] b5 bf [2] a1 a4 [2] ae be [2] b0 a3 [2] b2 a2 [2] a9 a4 [2] b5 a3 [2] a9 8c }

  condition:
    any of them
}