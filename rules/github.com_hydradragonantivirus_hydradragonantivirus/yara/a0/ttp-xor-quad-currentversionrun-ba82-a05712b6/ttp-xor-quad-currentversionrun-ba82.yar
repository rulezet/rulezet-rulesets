rule TTP_XOR_QUAD_CurrentVersionRun_ba82 {
  strings:
    $key_ba82 = { e9 ed [2] cd e3 [2] e6 cf [2] c8 ed [2] dc f6 [2] d3 ec [2] cd f1 [2] cf f0 [2] d4 f6 [2] c8 f1 [2] d4 de }

  condition:
    any of them
}