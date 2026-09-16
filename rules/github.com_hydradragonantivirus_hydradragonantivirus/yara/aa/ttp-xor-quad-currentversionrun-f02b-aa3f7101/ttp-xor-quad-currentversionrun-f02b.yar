rule TTP_XOR_QUAD_CurrentVersionRun_f02b {
  strings:
    $key_f02b = { a3 44 [2] 87 4a [2] ac 66 [2] 82 44 [2] 96 5f [2] 99 45 [2] 87 58 [2] 85 59 [2] 9e 5f [2] 82 58 [2] 9e 77 }

  condition:
    any of them
}