rule TTP_XOR_QUAD_CurrentVersionRun_3786 {
  strings:
    $key_3786 = { 64 e9 [2] 40 e7 [2] 6b cb [2] 45 e9 [2] 51 f2 [2] 5e e8 [2] 40 f5 [2] 42 f4 [2] 59 f2 [2] 45 f5 [2] 59 da }

  condition:
    any of them
}