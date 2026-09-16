rule TTP_XOR_QUAD_CurrentVersionRun_f768 {
  strings:
    $key_f768 = { a4 07 [2] 80 09 [2] ab 25 [2] 85 07 [2] 91 1c [2] 9e 06 [2] 80 1b [2] 82 1a [2] 99 1c [2] 85 1b [2] 99 34 }

  condition:
    any of them
}