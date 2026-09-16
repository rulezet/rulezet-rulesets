rule TTP_XOR_QUAD_CurrentVersionRun_f757 {
  strings:
    $key_f757 = { a4 38 [2] 80 36 [2] ab 1a [2] 85 38 [2] 91 23 [2] 9e 39 [2] 80 24 [2] 82 25 [2] 99 23 [2] 85 24 [2] 99 0b }

  condition:
    any of them
}