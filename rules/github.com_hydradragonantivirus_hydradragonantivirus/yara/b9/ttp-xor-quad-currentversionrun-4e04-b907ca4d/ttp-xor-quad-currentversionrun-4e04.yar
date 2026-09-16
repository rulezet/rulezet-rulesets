rule TTP_XOR_QUAD_CurrentVersionRun_4e04 {
  strings:
    $key_4e04 = { 1d 6b [2] 39 65 [2] 12 49 [2] 3c 6b [2] 28 70 [2] 27 6a [2] 39 77 [2] 3b 76 [2] 20 70 [2] 3c 77 [2] 20 58 }

  condition:
    any of them
}