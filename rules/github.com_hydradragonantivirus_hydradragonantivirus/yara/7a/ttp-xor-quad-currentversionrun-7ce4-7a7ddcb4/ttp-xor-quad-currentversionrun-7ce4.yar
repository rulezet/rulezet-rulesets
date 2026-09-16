rule TTP_XOR_QUAD_CurrentVersionRun_7ce4 {
  strings:
    $key_7ce4 = { 2f 8b [2] 0b 85 [2] 20 a9 [2] 0e 8b [2] 1a 90 [2] 15 8a [2] 0b 97 [2] 09 96 [2] 12 90 [2] 0e 97 [2] 12 b8 }

  condition:
    any of them
}