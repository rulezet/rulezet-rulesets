rule TTP_XOR_QUAD_CurrentVersionRun_0888 {
  strings:
    $key_0888 = { 5b e7 [2] 7f e9 [2] 54 c5 [2] 7a e7 [2] 6e fc [2] 61 e6 [2] 7f fb [2] 7d fa [2] 66 fc [2] 7a fb [2] 66 d4 }

  condition:
    any of them
}