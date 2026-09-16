rule TTP_XOR_QUAD_CurrentVersionRun_c9f2 {
  strings:
    $key_c9f2 = { 9a 9d [2] be 93 [2] 95 bf [2] bb 9d [2] af 86 [2] a0 9c [2] be 81 [2] bc 80 [2] a7 86 [2] bb 81 [2] a7 ae }

  condition:
    any of them
}