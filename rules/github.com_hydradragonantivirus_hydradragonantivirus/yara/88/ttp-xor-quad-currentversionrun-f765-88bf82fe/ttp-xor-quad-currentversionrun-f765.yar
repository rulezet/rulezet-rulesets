rule TTP_XOR_QUAD_CurrentVersionRun_f765 {
  strings:
    $key_f765 = { a4 0a [2] 80 04 [2] ab 28 [2] 85 0a [2] 91 11 [2] 9e 0b [2] 80 16 [2] 82 17 [2] 99 11 [2] 85 16 [2] 99 39 }

  condition:
    any of them
}