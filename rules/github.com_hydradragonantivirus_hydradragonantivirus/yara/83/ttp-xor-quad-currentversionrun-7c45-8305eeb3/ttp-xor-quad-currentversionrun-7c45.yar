rule TTP_XOR_QUAD_CurrentVersionRun_7c45 {
  strings:
    $key_7c45 = { 2f 2a [2] 0b 24 [2] 20 08 [2] 0e 2a [2] 1a 31 [2] 15 2b [2] 0b 36 [2] 09 37 [2] 12 31 [2] 0e 36 [2] 12 19 }

  condition:
    any of them
}