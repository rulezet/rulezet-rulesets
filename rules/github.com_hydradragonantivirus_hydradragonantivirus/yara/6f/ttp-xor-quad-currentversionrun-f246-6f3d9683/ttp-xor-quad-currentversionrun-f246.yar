rule TTP_XOR_QUAD_CurrentVersionRun_f246 {
  strings:
    $key_f246 = { a1 29 [2] 85 27 [2] ae 0b [2] 80 29 [2] 94 32 [2] 9b 28 [2] 85 35 [2] 87 34 [2] 9c 32 [2] 80 35 [2] 9c 1a }

  condition:
    any of them
}