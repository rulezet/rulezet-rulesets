rule TTP_XOR_QUAD_CurrentVersionRun_f688 {
  strings:
    $key_f688 = { a5 e7 [2] 81 e9 [2] aa c5 [2] 84 e7 [2] 90 fc [2] 9f e6 [2] 81 fb [2] 83 fa [2] 98 fc [2] 84 fb [2] 98 d4 }

  condition:
    any of them
}