rule TTP_XOR_QUAD_CurrentVersionRun_f505 {
  strings:
    $key_f505 = { a6 6a [2] 82 64 [2] a9 48 [2] 87 6a [2] 93 71 [2] 9c 6b [2] 82 76 [2] 80 77 [2] 9b 71 [2] 87 76 [2] 9b 59 }

  condition:
    any of them
}