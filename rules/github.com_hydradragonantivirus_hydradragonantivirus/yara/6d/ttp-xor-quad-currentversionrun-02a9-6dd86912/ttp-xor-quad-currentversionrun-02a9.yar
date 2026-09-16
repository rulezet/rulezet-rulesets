rule TTP_XOR_QUAD_CurrentVersionRun_02a9 {
  strings:
    $key_02a9 = { 51 c6 [2] 75 c8 [2] 5e e4 [2] 70 c6 [2] 64 dd [2] 6b c7 [2] 75 da [2] 77 db [2] 6c dd [2] 70 da [2] 6c f5 }

  condition:
    any of them
}