rule TTP_XOR_QUAD_CurrentVersionRun_f779 {
  strings:
    $key_f779 = { a4 16 [2] 80 18 [2] ab 34 [2] 85 16 [2] 91 0d [2] 9e 17 [2] 80 0a [2] 82 0b [2] 99 0d [2] 85 0a [2] 99 25 }

  condition:
    any of them
}