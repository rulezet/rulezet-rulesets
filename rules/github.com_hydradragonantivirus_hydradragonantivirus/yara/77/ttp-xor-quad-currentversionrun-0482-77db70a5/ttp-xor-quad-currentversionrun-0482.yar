rule TTP_XOR_QUAD_CurrentVersionRun_0482 {
  strings:
    $key_0482 = { 57 ed [2] 73 e3 [2] 58 cf [2] 76 ed [2] 62 f6 [2] 6d ec [2] 73 f1 [2] 71 f0 [2] 6a f6 [2] 76 f1 [2] 6a de }

  condition:
    any of them
}