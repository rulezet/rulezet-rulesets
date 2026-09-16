rule TTP_XOR_QUAD_CurrentVersionRun_4b88 {
  strings:
    $key_4b88 = { 18 e7 [2] 3c e9 [2] 17 c5 [2] 39 e7 [2] 2d fc [2] 22 e6 [2] 3c fb [2] 3e fa [2] 25 fc [2] 39 fb [2] 25 d4 }

  condition:
    any of them
}