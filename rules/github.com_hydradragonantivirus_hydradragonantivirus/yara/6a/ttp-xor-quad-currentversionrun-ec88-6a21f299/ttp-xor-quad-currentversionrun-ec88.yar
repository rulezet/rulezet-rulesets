rule TTP_XOR_QUAD_CurrentVersionRun_ec88 {
  strings:
    $key_ec88 = { bf e7 [2] 9b e9 [2] b0 c5 [2] 9e e7 [2] 8a fc [2] 85 e6 [2] 9b fb [2] 99 fa [2] 82 fc [2] 9e fb [2] 82 d4 }

  condition:
    any of them
}