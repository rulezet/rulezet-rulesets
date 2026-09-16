rule TTP_XOR_QUAD_CurrentVersionRun_b188 {
  strings:
    $key_b188 = { e2 e7 [2] c6 e9 [2] ed c5 [2] c3 e7 [2] d7 fc [2] d8 e6 [2] c6 fb [2] c4 fa [2] df fc [2] c3 fb [2] df d4 }

  condition:
    any of them
}