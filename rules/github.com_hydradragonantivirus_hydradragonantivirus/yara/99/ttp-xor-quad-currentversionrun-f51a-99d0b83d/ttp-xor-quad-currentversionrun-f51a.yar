rule TTP_XOR_QUAD_CurrentVersionRun_f51a {
  strings:
    $key_f51a = { a6 75 [2] 82 7b [2] a9 57 [2] 87 75 [2] 93 6e [2] 9c 74 [2] 82 69 [2] 80 68 [2] 9b 6e [2] 87 69 [2] 9b 46 }

  condition:
    any of them
}