rule TTP_XOR_QUAD_CurrentVersionRun_f486 {
  strings:
    $key_f486 = { a7 e9 [2] 83 e7 [2] a8 cb [2] 86 e9 [2] 92 f2 [2] 9d e8 [2] 83 f5 [2] 81 f4 [2] 9a f2 [2] 86 f5 [2] 9a da }

  condition:
    any of them
}