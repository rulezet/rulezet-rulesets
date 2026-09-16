rule TTP_XOR_QUAD_CurrentVersionRun_e088 {
  strings:
    $key_e088 = { b3 e7 [2] 97 e9 [2] bc c5 [2] 92 e7 [2] 86 fc [2] 89 e6 [2] 97 fb [2] 95 fa [2] 8e fc [2] 92 fb [2] 8e d4 }

  condition:
    any of them
}