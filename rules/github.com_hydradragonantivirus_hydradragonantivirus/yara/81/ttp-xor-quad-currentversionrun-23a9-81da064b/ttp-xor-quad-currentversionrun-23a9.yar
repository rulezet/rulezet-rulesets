rule TTP_XOR_QUAD_CurrentVersionRun_23a9 {
  strings:
    $key_23a9 = { 70 c6 [2] 54 c8 [2] 7f e4 [2] 51 c6 [2] 45 dd [2] 4a c7 [2] 54 da [2] 56 db [2] 4d dd [2] 51 da [2] 4d f5 }

  condition:
    any of them
}