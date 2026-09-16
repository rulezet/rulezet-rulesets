rule TTP_XOR_QUAD_CurrentVersionRun_fe97 {
  strings:
    $key_fe97 = { ad f8 [2] 89 f6 [2] a2 da [2] 8c f8 [2] 98 e3 [2] 97 f9 [2] 89 e4 [2] 8b e5 [2] 90 e3 [2] 8c e4 [2] 90 cb }

  condition:
    any of them
}