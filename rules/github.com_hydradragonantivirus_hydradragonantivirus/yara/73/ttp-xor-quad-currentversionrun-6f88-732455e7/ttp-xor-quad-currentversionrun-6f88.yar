rule TTP_XOR_QUAD_CurrentVersionRun_6f88 {
  strings:
    $key_6f88 = { 3c e7 [2] 18 e9 [2] 33 c5 [2] 1d e7 [2] 09 fc [2] 06 e6 [2] 18 fb [2] 1a fa [2] 01 fc [2] 1d fb [2] 01 d4 }

  condition:
    any of them
}