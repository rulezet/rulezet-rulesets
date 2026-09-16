rule TTP_XOR_QUAD_CurrentVersionRun_f2f8 {
  strings:
    $key_f2f8 = { a1 97 [2] 85 99 [2] ae b5 [2] 80 97 [2] 94 8c [2] 9b 96 [2] 85 8b [2] 87 8a [2] 9c 8c [2] 80 8b [2] 9c a4 }

  condition:
    any of them
}