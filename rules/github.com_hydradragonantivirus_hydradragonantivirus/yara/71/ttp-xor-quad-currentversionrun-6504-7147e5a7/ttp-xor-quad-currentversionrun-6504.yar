rule TTP_XOR_QUAD_CurrentVersionRun_6504 {
  strings:
    $key_6504 = { 36 6b [2] 12 65 [2] 39 49 [2] 17 6b [2] 03 70 [2] 0c 6a [2] 12 77 [2] 10 76 [2] 0b 70 [2] 17 77 [2] 0b 58 }

  condition:
    any of them
}