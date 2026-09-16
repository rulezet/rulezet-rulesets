rule TTP_XOR_QUAD_CurrentVersionRun_cbb2 {
  strings:
    $key_cbb2 = { 98 dd [2] bc d3 [2] 97 ff [2] b9 dd [2] ad c6 [2] a2 dc [2] bc c1 [2] be c0 [2] a5 c6 [2] b9 c1 [2] a5 ee }

  condition:
    any of them
}