rule TTP_XOR_QUAD_CurrentVersionRun_7aa9 {
  strings:
    $key_7aa9 = { 29 c6 [2] 0d c8 [2] 26 e4 [2] 08 c6 [2] 1c dd [2] 13 c7 [2] 0d da [2] 0f db [2] 14 dd [2] 08 da [2] 14 f5 }

  condition:
    any of them
}