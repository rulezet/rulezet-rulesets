rule TTP_XOR_QUAD_CurrentVersionRun_22a9 {
  strings:
    $key_22a9 = { 71 c6 [2] 55 c8 [2] 7e e4 [2] 50 c6 [2] 44 dd [2] 4b c7 [2] 55 da [2] 57 db [2] 4c dd [2] 50 da [2] 4c f5 }

  condition:
    any of them
}