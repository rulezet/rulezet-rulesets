rule TTP_XOR_QUAD_CurrentVersionRun_d28f {
  strings:
    $key_d28f = { 81 e0 [2] a5 ee [2] 8e c2 [2] a0 e0 [2] b4 fb [2] bb e1 [2] a5 fc [2] a7 fd [2] bc fb [2] a0 fc [2] bc d3 }

  condition:
    any of them
}