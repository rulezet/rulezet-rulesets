rule TTP_XOR_QUAD_CurrentVersionRun_ee94 {
  strings:
    $key_ee94 = { bd fb [2] 99 f5 [2] b2 d9 [2] 9c fb [2] 88 e0 [2] 87 fa [2] 99 e7 [2] 9b e6 [2] 80 e0 [2] 9c e7 [2] 80 c8 }

  condition:
    any of them
}