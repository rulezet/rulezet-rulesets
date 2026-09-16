rule TTP_XOR_QUAD_CurrentVersionRun_0548 {
  strings:
    $key_0548 = { 56 27 [2] 72 29 [2] 59 05 [2] 77 27 [2] 63 3c [2] 6c 26 [2] 72 3b [2] 70 3a [2] 6b 3c [2] 77 3b [2] 6b 14 }

  condition:
    any of them
}