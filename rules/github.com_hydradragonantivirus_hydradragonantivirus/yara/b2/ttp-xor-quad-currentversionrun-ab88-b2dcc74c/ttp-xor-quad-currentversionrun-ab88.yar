rule TTP_XOR_QUAD_CurrentVersionRun_ab88 {
  strings:
    $key_ab88 = { f8 e7 [2] dc e9 [2] f7 c5 [2] d9 e7 [2] cd fc [2] c2 e6 [2] dc fb [2] de fa [2] c5 fc [2] d9 fb [2] c5 d4 }

  condition:
    any of them
}