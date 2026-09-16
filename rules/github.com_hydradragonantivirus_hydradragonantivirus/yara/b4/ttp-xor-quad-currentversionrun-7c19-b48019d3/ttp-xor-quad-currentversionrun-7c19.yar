rule TTP_XOR_QUAD_CurrentVersionRun_7c19 {
  strings:
    $key_7c19 = { 2f 76 [2] 0b 78 [2] 20 54 [2] 0e 76 [2] 1a 6d [2] 15 77 [2] 0b 6a [2] 09 6b [2] 12 6d [2] 0e 6a [2] 12 45 }

  condition:
    any of them
}