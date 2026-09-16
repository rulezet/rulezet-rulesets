rule TTP_XOR_QUAD_CurrentVersionRun_ba97 {
  strings:
    $key_ba97 = { e9 f8 [2] cd f6 [2] e6 da [2] c8 f8 [2] dc e3 [2] d3 f9 [2] cd e4 [2] cf e5 [2] d4 e3 [2] c8 e4 [2] d4 cb }

  condition:
    any of them
}