rule TTP_XOR_QUAD_CurrentVersionRun_0f97 {
  strings:
    $key_0f97 = { 5c f8 [2] 78 f6 [2] 53 da [2] 7d f8 [2] 69 e3 [2] 66 f9 [2] 78 e4 [2] 7a e5 [2] 61 e3 [2] 7d e4 [2] 61 cb }

  condition:
    any of them
}