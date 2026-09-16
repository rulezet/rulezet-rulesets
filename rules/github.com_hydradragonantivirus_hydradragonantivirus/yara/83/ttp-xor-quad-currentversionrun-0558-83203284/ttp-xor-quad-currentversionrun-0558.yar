rule TTP_XOR_QUAD_CurrentVersionRun_0558 {
  strings:
    $key_0558 = { 56 37 [2] 72 39 [2] 59 15 [2] 77 37 [2] 63 2c [2] 6c 36 [2] 72 2b [2] 70 2a [2] 6b 2c [2] 77 2b [2] 6b 04 }

  condition:
    any of them
}