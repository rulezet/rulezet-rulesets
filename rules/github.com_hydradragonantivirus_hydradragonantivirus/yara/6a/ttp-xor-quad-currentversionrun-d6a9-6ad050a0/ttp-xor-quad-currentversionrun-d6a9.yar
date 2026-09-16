rule TTP_XOR_QUAD_CurrentVersionRun_d6a9 {
  strings:
    $key_d6a9 = { 85 c6 [2] a1 c8 [2] 8a e4 [2] a4 c6 [2] b0 dd [2] bf c7 [2] a1 da [2] a3 db [2] b8 dd [2] a4 da [2] b8 f5 }

  condition:
    any of them
}