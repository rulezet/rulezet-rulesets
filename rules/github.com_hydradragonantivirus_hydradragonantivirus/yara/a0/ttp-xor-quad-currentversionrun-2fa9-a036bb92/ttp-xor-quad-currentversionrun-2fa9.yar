rule TTP_XOR_QUAD_CurrentVersionRun_2fa9 {
  strings:
    $key_2fa9 = { 7c c6 [2] 58 c8 [2] 73 e4 [2] 5d c6 [2] 49 dd [2] 46 c7 [2] 58 da [2] 5a db [2] 41 dd [2] 5d da [2] 41 f5 }

  condition:
    any of them
}