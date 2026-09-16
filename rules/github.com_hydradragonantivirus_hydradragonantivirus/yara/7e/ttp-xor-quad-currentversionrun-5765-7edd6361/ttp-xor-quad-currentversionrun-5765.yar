rule TTP_XOR_QUAD_CurrentVersionRun_5765 {
  strings:
    $key_5765 = { 04 0a [2] 20 04 [2] 0b 28 [2] 25 0a [2] 31 11 [2] 3e 0b [2] 20 16 [2] 22 17 [2] 39 11 [2] 25 16 [2] 39 39 }

  condition:
    any of them
}