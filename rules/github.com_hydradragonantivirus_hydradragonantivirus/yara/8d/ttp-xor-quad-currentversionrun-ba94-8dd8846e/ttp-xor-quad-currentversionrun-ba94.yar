rule TTP_XOR_QUAD_CurrentVersionRun_ba94 {
  strings:
    $key_ba94 = { e9 fb [2] cd f5 [2] e6 d9 [2] c8 fb [2] dc e0 [2] d3 fa [2] cd e7 [2] cf e6 [2] d4 e0 [2] c8 e7 [2] d4 c8 }

  condition:
    any of them
}