rule TTP_XOR_QUAD_CurrentVersionRun_f748 {
  strings:
    $key_f748 = { a4 27 [2] 80 29 [2] ab 05 [2] 85 27 [2] 91 3c [2] 9e 26 [2] 80 3b [2] 82 3a [2] 99 3c [2] 85 3b [2] 99 14 }

  condition:
    any of them
}