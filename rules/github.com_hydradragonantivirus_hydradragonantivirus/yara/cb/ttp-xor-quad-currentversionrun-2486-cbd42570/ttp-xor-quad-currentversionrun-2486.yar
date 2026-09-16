rule TTP_XOR_QUAD_CurrentVersionRun_2486 {
  strings:
    $key_2486 = { 77 e9 [2] 53 e7 [2] 78 cb [2] 56 e9 [2] 42 f2 [2] 4d e8 [2] 53 f5 [2] 51 f4 [2] 4a f2 [2] 56 f5 [2] 4a da }

  condition:
    any of them
}