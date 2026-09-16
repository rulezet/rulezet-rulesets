rule TTP_XOR_QUAD_CurrentVersionRun_c98f {
  strings:
    $key_c98f = { 9a e0 [2] be ee [2] 95 c2 [2] bb e0 [2] af fb [2] a0 e1 [2] be fc [2] bc fd [2] a7 fb [2] bb fc [2] a7 d3 }

  condition:
    any of them
}