rule TTP_XOR_QUAD_CurrentVersionRun_c6d0 {
  strings:
    $key_c6d0 = { 95 bf [2] b1 b1 [2] 9a 9d [2] b4 bf [2] a0 a4 [2] af be [2] b1 a3 [2] b3 a2 [2] a8 a4 [2] b4 a3 [2] a8 8c }

  condition:
    any of them
}