rule TTP_XOR_QUAD_CurrentVersionRun_e482 {
  strings:
    $key_e482 = { b7 ed [2] 93 e3 [2] b8 cf [2] 96 ed [2] 82 f6 [2] 8d ec [2] 93 f1 [2] 91 f0 [2] 8a f6 [2] 96 f1 [2] 8a de }

  condition:
    any of them
}