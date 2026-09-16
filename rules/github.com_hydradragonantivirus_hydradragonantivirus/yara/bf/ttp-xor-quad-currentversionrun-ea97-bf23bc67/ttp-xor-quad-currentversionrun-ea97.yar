rule TTP_XOR_QUAD_CurrentVersionRun_ea97 {
  strings:
    $key_ea97 = { b9 f8 [2] 9d f6 [2] b6 da [2] 98 f8 [2] 8c e3 [2] 83 f9 [2] 9d e4 [2] 9f e5 [2] 84 e3 [2] 98 e4 [2] 84 cb }

  condition:
    any of them
}