rule TTP_XOR_QUAD_CurrentVersionRun_f288 {
  strings:
    $key_f288 = { a1 e7 [2] 85 e9 [2] ae c5 [2] 80 e7 [2] 94 fc [2] 9b e6 [2] 85 fb [2] 87 fa [2] 9c fc [2] 80 fb [2] 9c d4 }

  condition:
    any of them
}