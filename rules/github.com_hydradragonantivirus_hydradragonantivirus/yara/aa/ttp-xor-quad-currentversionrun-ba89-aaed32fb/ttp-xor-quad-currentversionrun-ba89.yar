rule TTP_XOR_QUAD_CurrentVersionRun_ba89 {
  strings:
    $key_ba89 = { e9 e6 [2] cd e8 [2] e6 c4 [2] c8 e6 [2] dc fd [2] d3 e7 [2] cd fa [2] cf fb [2] d4 fd [2] c8 fa [2] d4 d5 }

  condition:
    any of them
}