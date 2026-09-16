rule TTP_XOR_QUAD_CurrentVersionRun_2e04 {
  strings:
    $key_2e04 = { 7d 6b [2] 59 65 [2] 72 49 [2] 5c 6b [2] 48 70 [2] 47 6a [2] 59 77 [2] 5b 76 [2] 40 70 [2] 5c 77 [2] 40 58 }

  condition:
    any of them
}