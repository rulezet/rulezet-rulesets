rule TTP_XOR_QUAD_CurrentVersionRun_f436 {
  strings:
    $key_f436 = { a7 59 [2] 83 57 [2] a8 7b [2] 86 59 [2] 92 42 [2] 9d 58 [2] 83 45 [2] 81 44 [2] 9a 42 [2] 86 45 [2] 9a 6a }

  condition:
    any of them
}