rule TTP_XOR_QUAD_CurrentVersionRun_3e97 {
  strings:
    $key_3e97 = { 6d f8 [2] 49 f6 [2] 62 da [2] 4c f8 [2] 58 e3 [2] 57 f9 [2] 49 e4 [2] 4b e5 [2] 50 e3 [2] 4c e4 [2] 50 cb }

  condition:
    any of them
}