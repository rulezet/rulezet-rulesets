rule TTP_XOR_QUAD_CurrentVersionRun_f2a9 {
  strings:
    $key_f2a9 = { a1 c6 [2] 85 c8 [2] ae e4 [2] 80 c6 [2] 94 dd [2] 9b c7 [2] 85 da [2] 87 db [2] 9c dd [2] 80 da [2] 9c f5 }

  condition:
    any of them
}