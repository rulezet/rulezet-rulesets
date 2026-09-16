rule TTP_XOR_QUAD_CurrentVersionRun_d3b2 {
  strings:
    $key_d3b2 = { 80 dd [2] a4 d3 [2] 8f ff [2] a1 dd [2] b5 c6 [2] ba dc [2] a4 c1 [2] a6 c0 [2] bd c6 [2] a1 c1 [2] bd ee }

  condition:
    any of them
}