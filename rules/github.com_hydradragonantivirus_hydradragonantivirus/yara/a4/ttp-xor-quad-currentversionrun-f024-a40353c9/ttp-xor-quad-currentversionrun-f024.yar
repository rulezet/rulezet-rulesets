rule TTP_XOR_QUAD_CurrentVersionRun_f024 {
  strings:
    $key_f024 = { a3 4b [2] 87 45 [2] ac 69 [2] 82 4b [2] 96 50 [2] 99 4a [2] 87 57 [2] 85 56 [2] 9e 50 [2] 82 57 [2] 9e 78 }

  condition:
    any of them
}