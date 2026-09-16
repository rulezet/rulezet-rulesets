rule TTP_XOR_QUAD_CurrentVersionRun_1a97 {
  strings:
    $key_1a97 = { 49 f8 [2] 6d f6 [2] 46 da [2] 68 f8 [2] 7c e3 [2] 73 f9 [2] 6d e4 [2] 6f e5 [2] 74 e3 [2] 68 e4 [2] 74 cb }

  condition:
    any of them
}