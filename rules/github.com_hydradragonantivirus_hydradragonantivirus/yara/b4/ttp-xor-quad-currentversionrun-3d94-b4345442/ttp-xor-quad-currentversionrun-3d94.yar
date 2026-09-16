rule TTP_XOR_QUAD_CurrentVersionRun_3d94 {
  strings:
    $key_3d94 = { 6e fb [2] 4a f5 [2] 61 d9 [2] 4f fb [2] 5b e0 [2] 54 fa [2] 4a e7 [2] 48 e6 [2] 53 e0 [2] 4f e7 [2] 53 c8 }

  condition:
    any of them
}