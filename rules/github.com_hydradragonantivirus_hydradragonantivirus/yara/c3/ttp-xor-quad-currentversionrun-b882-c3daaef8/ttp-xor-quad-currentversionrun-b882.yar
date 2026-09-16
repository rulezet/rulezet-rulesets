rule TTP_XOR_QUAD_CurrentVersionRun_b882 {
  strings:
    $key_b882 = { eb ed [2] cf e3 [2] e4 cf [2] ca ed [2] de f6 [2] d1 ec [2] cf f1 [2] cd f0 [2] d6 f6 [2] ca f1 [2] d6 de }

  condition:
    any of them
}