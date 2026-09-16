rule TTP_XOR_QUAD_CurrentVersionRun_cead {
  strings:
    $key_cead = { 9d c2 [2] b9 cc [2] 92 e0 [2] bc c2 [2] a8 d9 [2] a7 c3 [2] b9 de [2] bb df [2] a0 d9 [2] bc de [2] a0 f1 }

  condition:
    any of them
}