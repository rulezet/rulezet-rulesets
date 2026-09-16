rule TTP_XOR_QUAD_CurrentVersionRun_2aa9 {
  strings:
    $key_2aa9 = { 79 c6 [2] 5d c8 [2] 76 e4 [2] 58 c6 [2] 4c dd [2] 43 c7 [2] 5d da [2] 5f db [2] 44 dd [2] 58 da [2] 44 f5 }

  condition:
    any of them
}