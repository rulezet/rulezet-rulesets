rule TTP_XOR_QUAD_CurrentVersionRun_d5f2 {
  strings:
    $key_d5f2 = { 86 9d [2] a2 93 [2] 89 bf [2] a7 9d [2] b3 86 [2] bc 9c [2] a2 81 [2] a0 80 [2] bb 86 [2] a7 81 [2] bb ae }

  condition:
    any of them
}