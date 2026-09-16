rule TTP_XOR_QUAD_CurrentVersionRun_e382 {
  strings:
    $key_e382 = { b0 ed [2] 94 e3 [2] bf cf [2] 91 ed [2] 85 f6 [2] 8a ec [2] 94 f1 [2] 96 f0 [2] 8d f6 [2] 91 f1 [2] 8d de }

  condition:
    any of them
}