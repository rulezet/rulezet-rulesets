rule TTP_XOR_QUAD_CurrentVersionRun_e288 {
  strings:
    $key_e288 = { b1 e7 [2] 95 e9 [2] be c5 [2] 90 e7 [2] 84 fc [2] 8b e6 [2] 95 fb [2] 97 fa [2] 8c fc [2] 90 fb [2] 8c d4 }

  condition:
    any of them
}