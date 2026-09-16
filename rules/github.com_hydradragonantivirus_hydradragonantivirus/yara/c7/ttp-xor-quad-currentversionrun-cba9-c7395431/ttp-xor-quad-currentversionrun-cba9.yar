rule TTP_XOR_QUAD_CurrentVersionRun_cba9 {
  strings:
    $key_cba9 = { 98 c6 [2] bc c8 [2] 97 e4 [2] b9 c6 [2] ad dd [2] a2 c7 [2] bc da [2] be db [2] a5 dd [2] b9 da [2] a5 f5 }

  condition:
    any of them
}