rule TTP_XOR_QUAD_CurrentVersionRun_f535 {
  strings:
    $key_f535 = { a6 5a [2] 82 54 [2] a9 78 [2] 87 5a [2] 93 41 [2] 9c 5b [2] 82 46 [2] 80 47 [2] 9b 41 [2] 87 46 [2] 9b 69 }

  condition:
    any of them
}