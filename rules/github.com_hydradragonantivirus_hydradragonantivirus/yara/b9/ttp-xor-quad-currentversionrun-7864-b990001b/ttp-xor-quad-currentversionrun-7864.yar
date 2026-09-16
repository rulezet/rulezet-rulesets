rule TTP_XOR_QUAD_CurrentVersionRun_7864 {
  strings:
    $key_7864 = { 2b 0b [2] 0f 05 [2] 24 29 [2] 0a 0b [2] 1e 10 [2] 11 0a [2] 0f 17 [2] 0d 16 [2] 16 10 [2] 0a 17 [2] 16 38 }

  condition:
    any of them
}