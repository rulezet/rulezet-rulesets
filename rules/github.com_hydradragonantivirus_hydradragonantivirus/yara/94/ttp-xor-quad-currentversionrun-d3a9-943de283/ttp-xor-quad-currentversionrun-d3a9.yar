rule TTP_XOR_QUAD_CurrentVersionRun_d3a9 {
  strings:
    $key_d3a9 = { 80 c6 [2] a4 c8 [2] 8f e4 [2] a1 c6 [2] b5 dd [2] ba c7 [2] a4 da [2] a6 db [2] bd dd [2] a1 da [2] bd f5 }

  condition:
    any of them
}