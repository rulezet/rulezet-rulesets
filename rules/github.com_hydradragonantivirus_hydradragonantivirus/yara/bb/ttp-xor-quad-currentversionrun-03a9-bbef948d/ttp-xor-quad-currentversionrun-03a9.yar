rule TTP_XOR_QUAD_CurrentVersionRun_03a9 {
  strings:
    $key_03a9 = { 50 c6 [2] 74 c8 [2] 5f e4 [2] 71 c6 [2] 65 dd [2] 6a c7 [2] 74 da [2] 76 db [2] 6d dd [2] 71 da [2] 6d f5 }

  condition:
    any of them
}