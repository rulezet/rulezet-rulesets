rule TTP_XOR_QUAD_CurrentVersionRun_64a9 {
  strings:
    $key_64a9 = { 37 c6 [2] 13 c8 [2] 38 e4 [2] 16 c6 [2] 02 dd [2] 0d c7 [2] 13 da [2] 11 db [2] 0a dd [2] 16 da [2] 0a f5 }

  condition:
    any of them
}