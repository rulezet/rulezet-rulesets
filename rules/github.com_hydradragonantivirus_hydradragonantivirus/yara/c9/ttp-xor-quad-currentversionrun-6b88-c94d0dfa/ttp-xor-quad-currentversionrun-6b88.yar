rule TTP_XOR_QUAD_CurrentVersionRun_6b88 {
  strings:
    $key_6b88 = { 38 e7 [2] 1c e9 [2] 37 c5 [2] 19 e7 [2] 0d fc [2] 02 e6 [2] 1c fb [2] 1e fa [2] 05 fc [2] 19 fb [2] 05 d4 }

  condition:
    any of them
}