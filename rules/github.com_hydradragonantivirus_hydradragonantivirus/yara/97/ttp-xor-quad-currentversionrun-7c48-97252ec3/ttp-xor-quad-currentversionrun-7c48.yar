rule TTP_XOR_QUAD_CurrentVersionRun_7c48 {
  strings:
    $key_7c48 = { 2f 27 [2] 0b 29 [2] 20 05 [2] 0e 27 [2] 1a 3c [2] 15 26 [2] 0b 3b [2] 09 3a [2] 12 3c [2] 0e 3b [2] 12 14 }

  condition:
    any of them
}