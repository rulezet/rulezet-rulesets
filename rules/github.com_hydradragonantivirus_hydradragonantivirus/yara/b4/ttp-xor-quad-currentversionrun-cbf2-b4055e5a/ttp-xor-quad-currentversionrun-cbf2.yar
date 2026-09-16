rule TTP_XOR_QUAD_CurrentVersionRun_cbf2 {
  strings:
    $key_cbf2 = { 98 9d [2] bc 93 [2] 97 bf [2] b9 9d [2] ad 86 [2] a2 9c [2] bc 81 [2] be 80 [2] a5 86 [2] b9 81 [2] a5 ae }

  condition:
    any of them
}