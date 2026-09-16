rule TTP_XOR_QUAD_CurrentVersionRun_619a {
  strings:
    $key_619a = { 32 f5 [2] 16 fb [2] 3d d7 [2] 13 f5 [2] 07 ee [2] 08 f4 [2] 16 e9 [2] 14 e8 [2] 0f ee [2] 13 e9 [2] 0f c6 }

  condition:
    any of them
}