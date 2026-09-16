rule TTP_XOR_QUAD_CurrentVersionRun_f77a {
  strings:
    $key_f77a = { a4 15 [2] 80 1b [2] ab 37 [2] 85 15 [2] 91 0e [2] 9e 14 [2] 80 09 [2] 82 08 [2] 99 0e [2] 85 09 [2] 99 26 }

  condition:
    any of them
}