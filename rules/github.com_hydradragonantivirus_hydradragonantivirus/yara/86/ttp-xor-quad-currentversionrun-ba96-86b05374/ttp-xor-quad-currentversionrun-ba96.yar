rule TTP_XOR_QUAD_CurrentVersionRun_ba96 {
  strings:
    $key_ba96 = { e9 f9 [2] cd f7 [2] e6 db [2] c8 f9 [2] dc e2 [2] d3 f8 [2] cd e5 [2] cf e4 [2] d4 e2 [2] c8 e5 [2] d4 ca }

  condition:
    any of them
}