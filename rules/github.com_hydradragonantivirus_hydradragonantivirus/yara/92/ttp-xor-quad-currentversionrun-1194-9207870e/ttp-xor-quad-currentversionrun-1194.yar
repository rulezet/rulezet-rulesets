rule TTP_XOR_QUAD_CurrentVersionRun_1194 {
  strings:
    $key_1194 = { 42 fb [2] 66 f5 [2] 4d d9 [2] 63 fb [2] 77 e0 [2] 78 fa [2] 66 e7 [2] 64 e6 [2] 7f e0 [2] 63 e7 [2] 7f c8 }

  condition:
    any of them
}