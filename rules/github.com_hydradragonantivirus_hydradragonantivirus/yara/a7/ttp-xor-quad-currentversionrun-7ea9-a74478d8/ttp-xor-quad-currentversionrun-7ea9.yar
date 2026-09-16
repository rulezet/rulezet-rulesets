rule TTP_XOR_QUAD_CurrentVersionRun_7ea9 {
  strings:
    $key_7ea9 = { 2d c6 [2] 09 c8 [2] 22 e4 [2] 0c c6 [2] 18 dd [2] 17 c7 [2] 09 da [2] 0b db [2] 10 dd [2] 0c da [2] 10 f5 }

  condition:
    any of them
}