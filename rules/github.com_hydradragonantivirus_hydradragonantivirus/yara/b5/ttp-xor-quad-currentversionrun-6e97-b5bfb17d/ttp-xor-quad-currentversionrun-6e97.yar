rule TTP_XOR_QUAD_CurrentVersionRun_6e97 {
  strings:
    $key_6e97 = { 3d f8 [2] 19 f6 [2] 32 da [2] 1c f8 [2] 08 e3 [2] 07 f9 [2] 19 e4 [2] 1b e5 [2] 00 e3 [2] 1c e4 [2] 00 cb }

  condition:
    any of them
}