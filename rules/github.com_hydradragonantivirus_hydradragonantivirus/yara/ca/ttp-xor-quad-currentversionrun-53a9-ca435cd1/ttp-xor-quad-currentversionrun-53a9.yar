rule TTP_XOR_QUAD_CurrentVersionRun_53a9 {
  strings:
    $key_53a9 = { 00 c6 [2] 24 c8 [2] 0f e4 [2] 21 c6 [2] 35 dd [2] 3a c7 [2] 24 da [2] 26 db [2] 3d dd [2] 21 da [2] 3d f5 }

  condition:
    any of them
}