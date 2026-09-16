rule TTP_XOR_QUAD_CurrentVersionRun_90b2 {
  strings:
    $key_90b2 = { c3 dd [2] e7 d3 [2] cc ff [2] e2 dd [2] f6 c6 [2] f9 dc [2] e7 c1 [2] e5 c0 [2] fe c6 [2] e2 c1 [2] fe ee }

  condition:
    any of them
}