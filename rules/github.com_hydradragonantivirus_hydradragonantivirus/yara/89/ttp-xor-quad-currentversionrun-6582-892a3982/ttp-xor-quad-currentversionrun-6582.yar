rule TTP_XOR_QUAD_CurrentVersionRun_6582 {
  strings:
    $key_6582 = { 36 ed [2] 12 e3 [2] 39 cf [2] 17 ed [2] 03 f6 [2] 0c ec [2] 12 f1 [2] 10 f0 [2] 0b f6 [2] 17 f1 [2] 0b de }

  condition:
    any of them
}