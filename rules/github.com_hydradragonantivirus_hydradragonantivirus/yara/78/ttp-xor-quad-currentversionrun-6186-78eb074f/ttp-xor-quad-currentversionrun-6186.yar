rule TTP_XOR_QUAD_CurrentVersionRun_6186 {
  strings:
    $key_6186 = { 32 e9 [2] 16 e7 [2] 3d cb [2] 13 e9 [2] 07 f2 [2] 08 e8 [2] 16 f5 [2] 14 f4 [2] 0f f2 [2] 13 f5 [2] 0f da }

  condition:
    any of them
}