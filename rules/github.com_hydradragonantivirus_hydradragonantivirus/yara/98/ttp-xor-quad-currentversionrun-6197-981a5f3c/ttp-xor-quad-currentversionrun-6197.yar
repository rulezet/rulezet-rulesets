rule TTP_XOR_QUAD_CurrentVersionRun_6197 {
  strings:
    $key_6197 = { 32 f8 [2] 16 f6 [2] 3d da [2] 13 f8 [2] 07 e3 [2] 08 f9 [2] 16 e4 [2] 14 e5 [2] 0f e3 [2] 13 e4 [2] 0f cb }

  condition:
    any of them
}