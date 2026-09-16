rule TTP_XOR_QUAD_CurrentVersionRun_44a9 {
  strings:
    $key_44a9 = { 17 c6 [2] 33 c8 [2] 18 e4 [2] 36 c6 [2] 22 dd [2] 2d c7 [2] 33 da [2] 31 db [2] 2a dd [2] 36 da [2] 2a f5 }

  condition:
    any of them
}