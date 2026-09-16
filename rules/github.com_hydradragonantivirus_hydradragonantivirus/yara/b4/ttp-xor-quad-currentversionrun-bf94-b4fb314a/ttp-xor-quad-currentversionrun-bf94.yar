rule TTP_XOR_QUAD_CurrentVersionRun_bf94 {
  strings:
    $key_bf94 = { ec fb [2] c8 f5 [2] e3 d9 [2] cd fb [2] d9 e0 [2] d6 fa [2] c8 e7 [2] ca e6 [2] d1 e0 [2] cd e7 [2] d1 c8 }

  condition:
    any of them
}