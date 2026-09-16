rule TTP_XOR_QUAD_CurrentVersionRun_7c79 {
  strings:
    $key_7c79 = { 2f 16 [2] 0b 18 [2] 20 34 [2] 0e 16 [2] 1a 0d [2] 15 17 [2] 0b 0a [2] 09 0b [2] 12 0d [2] 0e 0a [2] 12 25 }

  condition:
    any of them
}