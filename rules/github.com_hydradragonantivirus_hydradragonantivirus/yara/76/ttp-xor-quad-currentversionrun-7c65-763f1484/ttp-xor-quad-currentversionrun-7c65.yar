rule TTP_XOR_QUAD_CurrentVersionRun_7c65 {
  strings:
    $key_7c65 = { 2f 0a [2] 0b 04 [2] 20 28 [2] 0e 0a [2] 1a 11 [2] 15 0b [2] 0b 16 [2] 09 17 [2] 12 11 [2] 0e 16 [2] 12 39 }

  condition:
    any of them
}