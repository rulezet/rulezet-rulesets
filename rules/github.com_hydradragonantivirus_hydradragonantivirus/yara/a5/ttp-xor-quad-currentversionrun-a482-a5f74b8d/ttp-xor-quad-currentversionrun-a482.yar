rule TTP_XOR_QUAD_CurrentVersionRun_a482 {
  strings:
    $key_a482 = { f7 ed [2] d3 e3 [2] f8 cf [2] d6 ed [2] c2 f6 [2] cd ec [2] d3 f1 [2] d1 f0 [2] ca f6 [2] d6 f1 [2] ca de }

  condition:
    any of them
}