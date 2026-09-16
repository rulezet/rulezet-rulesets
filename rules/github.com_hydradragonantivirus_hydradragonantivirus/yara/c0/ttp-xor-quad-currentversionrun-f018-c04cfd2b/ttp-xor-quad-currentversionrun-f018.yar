rule TTP_XOR_QUAD_CurrentVersionRun_f018 {
  strings:
    $key_f018 = { a3 77 [2] 87 79 [2] ac 55 [2] 82 77 [2] 96 6c [2] 99 76 [2] 87 6b [2] 85 6a [2] 9e 6c [2] 82 6b [2] 9e 44 }

  condition:
    any of them
}