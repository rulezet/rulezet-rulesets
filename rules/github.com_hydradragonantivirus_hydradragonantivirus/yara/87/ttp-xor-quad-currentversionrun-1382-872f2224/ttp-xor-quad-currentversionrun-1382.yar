rule TTP_XOR_QUAD_CurrentVersionRun_1382 {
  strings:
    $key_1382 = { 40 ed [2] 64 e3 [2] 4f cf [2] 61 ed [2] 75 f6 [2] 7a ec [2] 64 f1 [2] 66 f0 [2] 7d f6 [2] 61 f1 [2] 7d de }

  condition:
    any of them
}