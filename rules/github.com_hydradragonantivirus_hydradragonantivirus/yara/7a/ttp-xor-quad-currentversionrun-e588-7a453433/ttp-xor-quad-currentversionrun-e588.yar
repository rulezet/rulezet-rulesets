rule TTP_XOR_QUAD_CurrentVersionRun_e588 {
  strings:
    $key_e588 = { b6 e7 [2] 92 e9 [2] b9 c5 [2] 97 e7 [2] 83 fc [2] 8c e6 [2] 92 fb [2] 90 fa [2] 8b fc [2] 97 fb [2] 8b d4 }

  condition:
    any of them
}