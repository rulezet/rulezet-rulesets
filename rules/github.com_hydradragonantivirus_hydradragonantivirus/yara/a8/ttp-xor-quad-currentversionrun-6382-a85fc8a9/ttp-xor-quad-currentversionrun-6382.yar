rule TTP_XOR_QUAD_CurrentVersionRun_6382 {
  strings:
    $key_6382 = { 30 ed [2] 14 e3 [2] 3f cf [2] 11 ed [2] 05 f6 [2] 0a ec [2] 14 f1 [2] 16 f0 [2] 0d f6 [2] 11 f1 [2] 0d de }

  condition:
    any of them
}