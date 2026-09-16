rule TTP_XOR_QUAD_CurrentVersionRun_2e65 {
  strings:
    $key_2e65 = { 7d 0a [2] 59 04 [2] 72 28 [2] 5c 0a [2] 48 11 [2] 47 0b [2] 59 16 [2] 5b 17 [2] 40 11 [2] 5c 16 [2] 40 39 }

  condition:
    any of them
}