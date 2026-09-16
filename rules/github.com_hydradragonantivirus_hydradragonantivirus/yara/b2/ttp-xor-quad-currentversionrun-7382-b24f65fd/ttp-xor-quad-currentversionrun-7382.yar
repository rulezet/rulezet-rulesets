rule TTP_XOR_QUAD_CurrentVersionRun_7382 {
  strings:
    $key_7382 = { 20 ed [2] 04 e3 [2] 2f cf [2] 01 ed [2] 15 f6 [2] 1a ec [2] 04 f1 [2] 06 f0 [2] 1d f6 [2] 01 f1 [2] 1d de }

  condition:
    any of them
}