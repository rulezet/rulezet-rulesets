rule TTP_XOR_QUAD_CurrentVersionRun_2ea9 {
  strings:
    $key_2ea9 = { 7d c6 [2] 59 c8 [2] 72 e4 [2] 5c c6 [2] 48 dd [2] 47 c7 [2] 59 da [2] 5b db [2] 40 dd [2] 5c da [2] 40 f5 }

  condition:
    any of them
}