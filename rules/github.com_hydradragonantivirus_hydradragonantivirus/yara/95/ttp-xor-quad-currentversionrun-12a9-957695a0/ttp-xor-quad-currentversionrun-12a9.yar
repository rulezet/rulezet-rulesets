rule TTP_XOR_QUAD_CurrentVersionRun_12a9 {
  strings:
    $key_12a9 = { 41 c6 [2] 65 c8 [2] 4e e4 [2] 60 c6 [2] 74 dd [2] 7b c7 [2] 65 da [2] 67 db [2] 7c dd [2] 60 da [2] 7c f5 }

  condition:
    any of them
}