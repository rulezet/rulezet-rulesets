rule TTP_XOR_QUAD_CurrentVersionRun_cbb4 {
  strings:
    $key_cbb4 = { 98 db [2] bc d5 [2] 97 f9 [2] b9 db [2] ad c0 [2] a2 da [2] bc c7 [2] be c6 [2] a5 c0 [2] b9 c7 [2] a5 e8 }

  condition:
    any of them
}