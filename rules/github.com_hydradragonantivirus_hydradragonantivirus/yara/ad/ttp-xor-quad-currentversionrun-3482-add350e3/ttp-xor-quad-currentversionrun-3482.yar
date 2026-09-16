rule TTP_XOR_QUAD_CurrentVersionRun_3482 {
  strings:
    $key_3482 = { 67 ed [2] 43 e3 [2] 68 cf [2] 46 ed [2] 52 f6 [2] 5d ec [2] 43 f1 [2] 41 f0 [2] 5a f6 [2] 46 f1 [2] 5a de }

  condition:
    any of them
}