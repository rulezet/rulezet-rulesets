rule TTP_XOR_QUAD_CurrentVersionRun_ba93 {
  strings:
    $key_ba93 = { e9 fc [2] cd f2 [2] e6 de [2] c8 fc [2] dc e7 [2] d3 fd [2] cd e0 [2] cf e1 [2] d4 e7 [2] c8 e0 [2] d4 cf }

  condition:
    any of them
}