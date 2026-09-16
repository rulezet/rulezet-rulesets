rule TTP_XOR_QUAD_CurrentVersionRun_0555 {
  strings:
    $key_0555 = { 56 3a [2] 72 34 [2] 59 18 [2] 77 3a [2] 63 21 [2] 6c 3b [2] 72 26 [2] 70 27 [2] 6b 21 [2] 77 26 [2] 6b 09 }

  condition:
    any of them
}