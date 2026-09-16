rule TTP_XOR_QUAD_CurrentVersionRun_f77b {
  strings:
    $key_f77b = { a4 14 [2] 80 1a [2] ab 36 [2] 85 14 [2] 91 0f [2] 9e 15 [2] 80 08 [2] 82 09 [2] 99 0f [2] 85 08 [2] 99 27 }

  condition:
    any of them
}