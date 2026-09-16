rule TTP_XOR_QUAD_CurrentVersionRun_f065 {
  strings:
    $key_f065 = { a3 0a [2] 87 04 [2] ac 28 [2] 82 0a [2] 96 11 [2] 99 0b [2] 87 16 [2] 85 17 [2] 9e 11 [2] 82 16 [2] 9e 39 }

  condition:
    any of them
}