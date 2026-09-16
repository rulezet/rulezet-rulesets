rule TTP_XOR_QUAD_CurrentVersionRun_62a9 {
  strings:
    $key_62a9 = { 31 c6 [2] 15 c8 [2] 3e e4 [2] 10 c6 [2] 04 dd [2] 0b c7 [2] 15 da [2] 17 db [2] 0c dd [2] 10 da [2] 0c f5 }

  condition:
    any of them
}