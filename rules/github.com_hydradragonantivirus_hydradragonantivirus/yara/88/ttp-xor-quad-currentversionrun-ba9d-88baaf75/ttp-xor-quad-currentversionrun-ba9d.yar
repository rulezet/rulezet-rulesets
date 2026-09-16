rule TTP_XOR_QUAD_CurrentVersionRun_ba9d {
  strings:
    $key_ba9d = { e9 f2 [2] cd fc [2] e6 d0 [2] c8 f2 [2] dc e9 [2] d3 f3 [2] cd ee [2] cf ef [2] d4 e9 [2] c8 ee [2] d4 c1 }

  condition:
    any of them
}