rule TTP_XOR_QUAD_CurrentVersionRun_3388 {
  strings:
    $key_3388 = { 60 e7 [2] 44 e9 [2] 6f c5 [2] 41 e7 [2] 55 fc [2] 5a e6 [2] 44 fb [2] 46 fa [2] 5d fc [2] 41 fb [2] 5d d4 }

  condition:
    any of them
}