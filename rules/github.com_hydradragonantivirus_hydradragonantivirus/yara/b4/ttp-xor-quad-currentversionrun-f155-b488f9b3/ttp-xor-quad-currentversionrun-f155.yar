rule TTP_XOR_QUAD_CurrentVersionRun_f155 {
  strings:
    $key_f155 = { a2 3a [2] 86 34 [2] ad 18 [2] 83 3a [2] 97 21 [2] 98 3b [2] 86 26 [2] 84 27 [2] 9f 21 [2] 83 26 [2] 9f 09 }

  condition:
    any of them
}