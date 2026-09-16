rule TTP_XOR_QUAD_CurrentVersionRun_b488 {
  strings:
    $key_b488 = { e7 e7 [2] c3 e9 [2] e8 c5 [2] c6 e7 [2] d2 fc [2] dd e6 [2] c3 fb [2] c1 fa [2] da fc [2] c6 fb [2] da d4 }

  condition:
    any of them
}