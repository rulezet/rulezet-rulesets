rule TTP_XOR_QUAD_CurrentVersionRun_6187 {
  strings:
    $key_6187 = { 32 e8 [2] 16 e6 [2] 3d ca [2] 13 e8 [2] 07 f3 [2] 08 e9 [2] 16 f4 [2] 14 f5 [2] 0f f3 [2] 13 f4 [2] 0f db }

  condition:
    any of them
}