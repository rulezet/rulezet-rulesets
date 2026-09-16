rule TTP_XOR_QUAD_CurrentVersionRun_d2d0 {
  strings:
    $key_d2d0 = { 81 bf [2] a5 b1 [2] 8e 9d [2] a0 bf [2] b4 a4 [2] bb be [2] a5 a3 [2] a7 a2 [2] bc a4 [2] a0 a3 [2] bc 8c }

  condition:
    any of them
}