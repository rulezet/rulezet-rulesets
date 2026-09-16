rule TTP_XOR_QUAD_CurrentVersionRun_0579 {
  strings:
    $key_0579 = { 56 16 [2] 72 18 [2] 59 34 [2] 77 16 [2] 63 0d [2] 6c 17 [2] 72 0a [2] 70 0b [2] 6b 0d [2] 77 0a [2] 6b 25 }

  condition:
    any of them
}