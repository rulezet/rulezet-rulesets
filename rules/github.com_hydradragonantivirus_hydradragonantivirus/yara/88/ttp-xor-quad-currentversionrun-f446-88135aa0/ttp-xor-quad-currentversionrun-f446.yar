rule TTP_XOR_QUAD_CurrentVersionRun_f446 {
  strings:
    $key_f446 = { a7 29 [2] 83 27 [2] a8 0b [2] 86 29 [2] 92 32 [2] 9d 28 [2] 83 35 [2] 81 34 [2] 9a 32 [2] 86 35 [2] 9a 1a }

  condition:
    any of them
}