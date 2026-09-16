rule TTP_XOR_QUAD_CurrentVersionRun_2188 {
  strings:
    $key_2188 = { 72 e7 [2] 56 e9 [2] 7d c5 [2] 53 e7 [2] 47 fc [2] 48 e6 [2] 56 fb [2] 54 fa [2] 4f fc [2] 53 fb [2] 4f d4 }

  condition:
    any of them
}