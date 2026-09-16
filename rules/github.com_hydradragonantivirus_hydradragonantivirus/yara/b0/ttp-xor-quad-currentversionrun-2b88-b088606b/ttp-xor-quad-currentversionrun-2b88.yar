rule TTP_XOR_QUAD_CurrentVersionRun_2b88 {
  strings:
    $key_2b88 = { 78 e7 [2] 5c e9 [2] 77 c5 [2] 59 e7 [2] 4d fc [2] 42 e6 [2] 5c fb [2] 5e fa [2] 45 fc [2] 59 fb [2] 45 d4 }

  condition:
    any of them
}