rule TTP_XOR_QUAD_CurrentVersionRun_5565 {
  strings:
    $key_5565 = { 06 0a [2] 22 04 [2] 09 28 [2] 27 0a [2] 33 11 [2] 3c 0b [2] 22 16 [2] 20 17 [2] 3b 11 [2] 27 16 [2] 3b 39 }

  condition:
    any of them
}