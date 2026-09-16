rule TTP_XOR_QUAD_CurrentVersionRun_6265 {
  strings:
    $key_6265 = { 31 0a [2] 15 04 [2] 3e 28 [2] 10 0a [2] 04 11 [2] 0b 0b [2] 15 16 [2] 17 17 [2] 0c 11 [2] 10 16 [2] 0c 39 }

  condition:
    any of them
}