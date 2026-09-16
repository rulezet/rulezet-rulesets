rule TTP_XOR_QUAD_CurrentVersionRun_f747 {
  strings:
    $key_f747 = { a4 28 [2] 80 26 [2] ab 0a [2] 85 28 [2] 91 33 [2] 9e 29 [2] 80 34 [2] 82 35 [2] 99 33 [2] 85 34 [2] 99 1b }

  condition:
    any of them
}