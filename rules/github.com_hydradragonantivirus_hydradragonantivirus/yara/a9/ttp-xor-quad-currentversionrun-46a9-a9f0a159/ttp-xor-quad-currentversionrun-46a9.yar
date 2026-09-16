rule TTP_XOR_QUAD_CurrentVersionRun_46a9 {
  strings:
    $key_46a9 = { 15 c6 [2] 31 c8 [2] 1a e4 [2] 34 c6 [2] 20 dd [2] 2f c7 [2] 31 da [2] 33 db [2] 28 dd [2] 34 da [2] 28 f5 }

  condition:
    any of them
}