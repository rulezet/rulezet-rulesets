rule TTP_XOR_QUAD_CurrentVersionRun_4d88 {
  strings:
    $key_4d88 = { 1e e7 [2] 3a e9 [2] 11 c5 [2] 3f e7 [2] 2b fc [2] 24 e6 [2] 3a fb [2] 38 fa [2] 23 fc [2] 3f fb [2] 23 d4 }

  condition:
    any of them
}