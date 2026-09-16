rule TTP_XOR_QUAD_CurrentVersionRun_f4a6 {
  strings:
    $key_f4a6 = { a7 c9 [2] 83 c7 [2] a8 eb [2] 86 c9 [2] 92 d2 [2] 9d c8 [2] 83 d5 [2] 81 d4 [2] 9a d2 [2] 86 d5 [2] 9a fa }

  condition:
    any of them
}