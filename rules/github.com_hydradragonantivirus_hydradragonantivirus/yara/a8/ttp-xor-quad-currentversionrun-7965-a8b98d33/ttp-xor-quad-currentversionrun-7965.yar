rule TTP_XOR_QUAD_CurrentVersionRun_7965 {
  strings:
    $key_7965 = { 2a 0a [2] 0e 04 [2] 25 28 [2] 0b 0a [2] 1f 11 [2] 10 0b [2] 0e 16 [2] 0c 17 [2] 17 11 [2] 0b 16 [2] 17 39 }

  condition:
    any of them
}