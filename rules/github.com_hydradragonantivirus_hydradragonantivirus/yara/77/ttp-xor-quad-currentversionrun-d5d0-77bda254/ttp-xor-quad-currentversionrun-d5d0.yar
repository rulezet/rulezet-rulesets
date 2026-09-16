rule TTP_XOR_QUAD_CurrentVersionRun_d5d0 {
  strings:
    $key_d5d0 = { 86 bf [2] a2 b1 [2] 89 9d [2] a7 bf [2] b3 a4 [2] bc be [2] a2 a3 [2] a0 a2 [2] bb a4 [2] a7 a3 [2] bb 8c }

  condition:
    any of them
}