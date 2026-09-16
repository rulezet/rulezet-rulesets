rule TTP_XOR_QUAD_CurrentVersionRun_f524 {
  strings:
    $key_f524 = { a6 4b [2] 82 45 [2] a9 69 [2] 87 4b [2] 93 50 [2] 9c 4a [2] 82 57 [2] 80 56 [2] 9b 50 [2] 87 57 [2] 9b 78 }

  condition:
    any of them
}