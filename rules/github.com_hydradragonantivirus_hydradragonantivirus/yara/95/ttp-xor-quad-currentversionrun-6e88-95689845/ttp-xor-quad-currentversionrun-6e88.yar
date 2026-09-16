rule TTP_XOR_QUAD_CurrentVersionRun_6e88 {
  strings:
    $key_6e88 = { 3d e7 [2] 19 e9 [2] 32 c5 [2] 1c e7 [2] 08 fc [2] 07 e6 [2] 19 fb [2] 1b fa [2] 00 fc [2] 1c fb [2] 00 d4 }

  condition:
    any of them
}