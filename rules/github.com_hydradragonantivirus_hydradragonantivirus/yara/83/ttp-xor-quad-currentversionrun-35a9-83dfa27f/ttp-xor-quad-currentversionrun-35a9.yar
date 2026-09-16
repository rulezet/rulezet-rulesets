rule TTP_XOR_QUAD_CurrentVersionRun_35a9 {
  strings:
    $key_35a9 = { 66 c6 [2] 42 c8 [2] 69 e4 [2] 47 c6 [2] 53 dd [2] 5c c7 [2] 42 da [2] 40 db [2] 5b dd [2] 47 da [2] 5b f5 }

  condition:
    any of them
}