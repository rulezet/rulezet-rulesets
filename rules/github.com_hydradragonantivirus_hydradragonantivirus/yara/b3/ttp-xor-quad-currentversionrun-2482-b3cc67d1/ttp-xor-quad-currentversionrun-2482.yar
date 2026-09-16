rule TTP_XOR_QUAD_CurrentVersionRun_2482 {
  strings:
    $key_2482 = { 77 ed [2] 53 e3 [2] 78 cf [2] 56 ed [2] 42 f6 [2] 4d ec [2] 53 f1 [2] 51 f0 [2] 4a f6 [2] 56 f1 [2] 4a de }

  condition:
    any of them
}