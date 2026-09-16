rule TTP_XOR_QUAD_CurrentVersionRun_cf94 {
  strings:
    $key_cf94 = { 9c fb [2] b8 f5 [2] 93 d9 [2] bd fb [2] a9 e0 [2] a6 fa [2] b8 e7 [2] ba e6 [2] a1 e0 [2] bd e7 [2] a1 c8 }

  condition:
    any of them
}