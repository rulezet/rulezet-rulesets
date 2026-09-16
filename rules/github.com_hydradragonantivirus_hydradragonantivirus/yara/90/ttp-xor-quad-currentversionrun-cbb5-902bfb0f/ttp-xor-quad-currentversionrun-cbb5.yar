rule TTP_XOR_QUAD_CurrentVersionRun_cbb5 {
  strings:
    $key_cbb5 = { 98 da [2] bc d4 [2] 97 f8 [2] b9 da [2] ad c1 [2] a2 db [2] bc c6 [2] be c7 [2] a5 c1 [2] b9 c6 [2] a5 e9 }

  condition:
    any of them
}