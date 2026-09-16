rule TTP_XOR_QUAD_CurrentVersionRun_7c24 {
  strings:
    $key_7c24 = { 2f 4b [2] 0b 45 [2] 20 69 [2] 0e 4b [2] 1a 50 [2] 15 4a [2] 0b 57 [2] 09 56 [2] 12 50 [2] 0e 57 [2] 12 78 }

  condition:
    any of them
}