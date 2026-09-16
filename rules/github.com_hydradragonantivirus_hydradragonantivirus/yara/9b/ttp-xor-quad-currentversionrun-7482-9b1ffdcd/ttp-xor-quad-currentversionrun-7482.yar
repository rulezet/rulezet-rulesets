rule TTP_XOR_QUAD_CurrentVersionRun_7482 {
  strings:
    $key_7482 = { 27 ed [2] 03 e3 [2] 28 cf [2] 06 ed [2] 12 f6 [2] 1d ec [2] 03 f1 [2] 01 f0 [2] 1a f6 [2] 06 f1 [2] 1a de }

  condition:
    any of them
}