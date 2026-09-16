rule TTP_XOR_QUAD_CurrentVersionRun_a688 {
  strings:
    $key_a688 = { f5 e7 [2] d1 e9 [2] fa c5 [2] d4 e7 [2] c0 fc [2] cf e6 [2] d1 fb [2] d3 fa [2] c8 fc [2] d4 fb [2] c8 d4 }

  condition:
    any of them
}