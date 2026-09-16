rule TTP_XOR_QUAD_CurrentVersionRun_a8df {
  strings:
    $key_a8df = { fb b0 [2] df be [2] f4 92 [2] da b0 [2] ce ab [2] c1 b1 [2] df ac [2] dd ad [2] c6 ab [2] da ac [2] c6 83 }

  condition:
    any of them
}