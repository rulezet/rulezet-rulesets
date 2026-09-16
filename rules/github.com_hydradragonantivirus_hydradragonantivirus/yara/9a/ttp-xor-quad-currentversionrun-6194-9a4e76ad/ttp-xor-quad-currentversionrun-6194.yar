rule TTP_XOR_QUAD_CurrentVersionRun_6194 {
  strings:
    $key_6194 = { 32 fb [2] 16 f5 [2] 3d d9 [2] 13 fb [2] 07 e0 [2] 08 fa [2] 16 e7 [2] 14 e6 [2] 0f e0 [2] 13 e7 [2] 0f c8 }

  condition:
    any of them
}