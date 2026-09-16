rule TTP_XOR_QUAD_CurrentVersionRun_bf89 {
  strings:
    $key_bf89 = { ec e6 [2] c8 e8 [2] e3 c4 [2] cd e6 [2] d9 fd [2] d6 e7 [2] c8 fa [2] ca fb [2] d1 fd [2] cd fa [2] d1 d5 }

  condition:
    any of them
}