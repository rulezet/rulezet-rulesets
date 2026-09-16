rule TTP_XOR_QUAD_CurrentVersionRun_f758 {
  strings:
    $key_f758 = { a4 37 [2] 80 39 [2] ab 15 [2] 85 37 [2] 91 2c [2] 9e 36 [2] 80 2b [2] 82 2a [2] 99 2c [2] 85 2b [2] 99 04 }

  condition:
    any of them
}