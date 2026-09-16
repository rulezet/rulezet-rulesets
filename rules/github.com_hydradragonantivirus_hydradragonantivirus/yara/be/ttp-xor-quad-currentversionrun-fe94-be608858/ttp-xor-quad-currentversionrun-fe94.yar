rule TTP_XOR_QUAD_CurrentVersionRun_fe94 {
  strings:
    $key_fe94 = { ad fb [2] 89 f5 [2] a2 d9 [2] 8c fb [2] 98 e0 [2] 97 fa [2] 89 e7 [2] 8b e6 [2] 90 e0 [2] 8c e7 [2] 90 c8 }

  condition:
    any of them
}