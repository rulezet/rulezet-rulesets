rule TTP_XOR_QUAD_CurrentVersionRun_e294 {
  strings:
    $key_e294 = { b1 fb [2] 95 f5 [2] be d9 [2] 90 fb [2] 84 e0 [2] 8b fa [2] 95 e7 [2] 97 e6 [2] 8c e0 [2] 90 e7 [2] 8c c8 }

  condition:
    any of them
}