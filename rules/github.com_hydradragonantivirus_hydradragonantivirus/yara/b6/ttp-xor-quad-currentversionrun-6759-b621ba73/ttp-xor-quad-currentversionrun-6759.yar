rule TTP_XOR_QUAD_CurrentVersionRun_6759 {
  strings:
    $key_6759 = { 34 36 [2] 10 38 [2] 3b 14 [2] 15 36 [2] 01 2d [2] 0e 37 [2] 10 2a [2] 12 2b [2] 09 2d [2] 15 2a [2] 09 05 }

  condition:
    any of them
}