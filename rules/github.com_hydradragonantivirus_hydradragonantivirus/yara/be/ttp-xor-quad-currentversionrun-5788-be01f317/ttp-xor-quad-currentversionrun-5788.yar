rule TTP_XOR_QUAD_CurrentVersionRun_5788 {
  strings:
    $key_5788 = { 04 e7 [2] 20 e9 [2] 0b c5 [2] 25 e7 [2] 31 fc [2] 3e e6 [2] 20 fb [2] 22 fa [2] 39 fc [2] 25 fb [2] 39 d4 }

  condition:
    any of them
}