rule TTP_XOR_QUAD_CurrentVersionRun_7788 {
  strings:
    $key_7788 = { 24 e7 [2] 00 e9 [2] 2b c5 [2] 05 e7 [2] 11 fc [2] 1e e6 [2] 00 fb [2] 02 fa [2] 19 fc [2] 05 fb [2] 19 d4 }

  condition:
    any of them
}