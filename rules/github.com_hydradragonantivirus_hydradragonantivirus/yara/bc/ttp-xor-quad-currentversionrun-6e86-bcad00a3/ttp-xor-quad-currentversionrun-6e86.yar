rule TTP_XOR_QUAD_CurrentVersionRun_6e86 {
  strings:
    $key_6e86 = { 3d e9 [2] 19 e7 [2] 32 cb [2] 1c e9 [2] 08 f2 [2] 07 e8 [2] 19 f5 [2] 1b f4 [2] 00 f2 [2] 1c f5 [2] 00 da }

  condition:
    any of them
}