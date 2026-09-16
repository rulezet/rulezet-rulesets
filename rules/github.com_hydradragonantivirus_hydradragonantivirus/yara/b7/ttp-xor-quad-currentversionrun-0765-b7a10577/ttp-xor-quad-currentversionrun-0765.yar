rule TTP_XOR_QUAD_CurrentVersionRun_0765 {
  strings:
    $key_0765 = { 54 0a [2] 70 04 [2] 5b 28 [2] 75 0a [2] 61 11 [2] 6e 0b [2] 70 16 [2] 72 17 [2] 69 11 [2] 75 16 [2] 69 39 }

  condition:
    any of them
}