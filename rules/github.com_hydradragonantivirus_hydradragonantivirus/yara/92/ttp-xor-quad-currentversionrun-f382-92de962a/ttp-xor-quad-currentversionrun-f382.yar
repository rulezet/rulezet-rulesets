rule TTP_XOR_QUAD_CurrentVersionRun_f382 {
  strings:
    $key_f382 = { a0 ed [2] 84 e3 [2] af cf [2] 81 ed [2] 95 f6 [2] 9a ec [2] 84 f1 [2] 86 f0 [2] 9d f6 [2] 81 f1 [2] 9d de }

  condition:
    any of them
}