rule TTP_XOR_QUAD_CurrentVersionRun_3d95 {
  strings:
    $key_3d95 = { 6e fa [2] 4a f4 [2] 61 d8 [2] 4f fa [2] 5b e1 [2] 54 fb [2] 4a e6 [2] 48 e7 [2] 53 e1 [2] 4f e6 [2] 53 c9 }

  condition:
    any of them
}