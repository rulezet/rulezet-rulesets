rule TTP_XOR_QUAD_CurrentVersionRun_f025 {
  strings:
    $key_f025 = { a3 4a [2] 87 44 [2] ac 68 [2] 82 4a [2] 96 51 [2] 99 4b [2] 87 56 [2] 85 57 [2] 9e 51 [2] 82 56 [2] 9e 79 }

  condition:
    any of them
}