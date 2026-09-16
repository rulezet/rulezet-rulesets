rule TTP_XOR_QUAD_CurrentVersionRun_f0f8 {
  strings:
    $key_f0f8 = { a3 97 [2] 87 99 [2] ac b5 [2] 82 97 [2] 96 8c [2] 99 96 [2] 87 8b [2] 85 8a [2] 9e 8c [2] 82 8b [2] 9e a4 }

  condition:
    any of them
}