rule TTP_XOR_QUAD_CurrentVersionRun_2588 {
  strings:
    $key_2588 = { 76 e7 [2] 52 e9 [2] 79 c5 [2] 57 e7 [2] 43 fc [2] 4c e6 [2] 52 fb [2] 50 fa [2] 4b fc [2] 57 fb [2] 4b d4 }

  condition:
    any of them
}