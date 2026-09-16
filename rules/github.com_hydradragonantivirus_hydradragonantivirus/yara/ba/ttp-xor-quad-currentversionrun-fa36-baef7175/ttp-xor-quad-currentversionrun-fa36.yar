rule TTP_XOR_QUAD_CurrentVersionRun_fa36 {
  strings:
    $key_fa36 = { a9 59 [2] 8d 57 [2] a6 7b [2] 88 59 [2] 9c 42 [2] 93 58 [2] 8d 45 [2] 8f 44 [2] 94 42 [2] 88 45 [2] 94 6a }

  condition:
    any of them
}