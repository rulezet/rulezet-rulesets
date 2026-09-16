rule TTP_XOR_QUAD_CurrentVersionRun_7188 {
  strings:
    $key_7188 = { 22 e7 [2] 06 e9 [2] 2d c5 [2] 03 e7 [2] 17 fc [2] 18 e6 [2] 06 fb [2] 04 fa [2] 1f fc [2] 03 fb [2] 1f d4 }

  condition:
    any of them
}