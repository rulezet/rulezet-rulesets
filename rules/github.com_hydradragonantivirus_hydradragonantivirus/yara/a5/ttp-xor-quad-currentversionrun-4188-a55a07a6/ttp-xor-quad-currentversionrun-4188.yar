rule TTP_XOR_QUAD_CurrentVersionRun_4188 {
  strings:
    $key_4188 = { 12 e7 [2] 36 e9 [2] 1d c5 [2] 33 e7 [2] 27 fc [2] 28 e6 [2] 36 fb [2] 34 fa [2] 2f fc [2] 33 fb [2] 2f d4 }

  condition:
    any of them
}