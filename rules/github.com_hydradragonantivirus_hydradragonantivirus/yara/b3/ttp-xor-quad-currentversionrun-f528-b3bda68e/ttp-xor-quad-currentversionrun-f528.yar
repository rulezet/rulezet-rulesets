rule TTP_XOR_QUAD_CurrentVersionRun_f528 {
  strings:
    $key_f528 = { a6 47 [2] 82 49 [2] a9 65 [2] 87 47 [2] 93 5c [2] 9c 46 [2] 82 5b [2] 80 5a [2] 9b 5c [2] 87 5b [2] 9b 74 }

  condition:
    any of them
}