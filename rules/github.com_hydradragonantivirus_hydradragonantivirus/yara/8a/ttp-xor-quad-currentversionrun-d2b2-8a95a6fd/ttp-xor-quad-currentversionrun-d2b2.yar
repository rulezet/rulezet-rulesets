rule TTP_XOR_QUAD_CurrentVersionRun_d2b2 {
  strings:
    $key_d2b2 = { 81 dd [2] a5 d3 [2] 8e ff [2] a0 dd [2] b4 c6 [2] bb dc [2] a5 c1 [2] a7 c0 [2] bc c6 [2] a0 c1 [2] bc ee }

  condition:
    any of them
}