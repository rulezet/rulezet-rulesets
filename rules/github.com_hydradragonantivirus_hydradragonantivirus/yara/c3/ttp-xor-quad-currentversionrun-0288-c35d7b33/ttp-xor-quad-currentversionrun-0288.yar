rule TTP_XOR_QUAD_CurrentVersionRun_0288 {
  strings:
    $key_0288 = { 51 e7 [2] 75 e9 [2] 5e c5 [2] 70 e7 [2] 64 fc [2] 6b e6 [2] 75 fb [2] 77 fa [2] 6c fc [2] 70 fb [2] 6c d4 }

  condition:
    any of them
}