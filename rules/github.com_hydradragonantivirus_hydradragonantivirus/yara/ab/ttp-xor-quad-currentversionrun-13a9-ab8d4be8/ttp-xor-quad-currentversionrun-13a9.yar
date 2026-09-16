rule TTP_XOR_QUAD_CurrentVersionRun_13a9 {
  strings:
    $key_13a9 = { 40 c6 [2] 64 c8 [2] 4f e4 [2] 61 c6 [2] 75 dd [2] 7a c7 [2] 64 da [2] 66 db [2] 7d dd [2] 61 da [2] 7d f5 }

  condition:
    any of them
}