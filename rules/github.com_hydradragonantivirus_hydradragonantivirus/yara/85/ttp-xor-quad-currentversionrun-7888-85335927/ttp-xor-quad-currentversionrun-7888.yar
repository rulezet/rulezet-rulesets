rule TTP_XOR_QUAD_CurrentVersionRun_7888 {
  strings:
    $key_7888 = { 2b e7 [2] 0f e9 [2] 24 c5 [2] 0a e7 [2] 1e fc [2] 11 e6 [2] 0f fb [2] 0d fa [2] 16 fc [2] 0a fb [2] 16 d4 }

  condition:
    any of them
}