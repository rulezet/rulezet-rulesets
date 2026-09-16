rule TTP_XOR_QUAD_CurrentVersionRun_f77c {
  strings:
    $key_f77c = { a4 13 [2] 80 1d [2] ab 31 [2] 85 13 [2] 91 08 [2] 9e 12 [2] 80 0f [2] 82 0e [2] 99 08 [2] 85 0f [2] 99 20 }

  condition:
    any of them
}