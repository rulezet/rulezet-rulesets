rule TTP_XOR_QUAD_CurrentVersionRun_d0a9 {
  strings:
    $key_d0a9 = { 83 c6 [2] a7 c8 [2] 8c e4 [2] a2 c6 [2] b6 dd [2] b9 c7 [2] a7 da [2] a5 db [2] be dd [2] a2 da [2] be f5 }

  condition:
    any of them
}