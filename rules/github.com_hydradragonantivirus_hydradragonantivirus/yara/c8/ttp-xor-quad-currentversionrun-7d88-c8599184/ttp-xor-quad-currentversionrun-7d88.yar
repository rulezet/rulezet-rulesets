rule TTP_XOR_QUAD_CurrentVersionRun_7d88 {
  strings:
    $key_7d88 = { 2e e7 [2] 0a e9 [2] 21 c5 [2] 0f e7 [2] 1b fc [2] 14 e6 [2] 0a fb [2] 08 fa [2] 13 fc [2] 0f fb [2] 13 d4 }

  condition:
    any of them
}