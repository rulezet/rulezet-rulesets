rule TTP_XOR_QUAD_CurrentVersionRun_6565 {
  strings:
    $key_6565 = { 36 0a [2] 12 04 [2] 39 28 [2] 17 0a [2] 03 11 [2] 0c 0b [2] 12 16 [2] 10 17 [2] 0b 11 [2] 17 16 [2] 0b 39 }

  condition:
    any of them
}