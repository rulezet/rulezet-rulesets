rule TTP_XOR_QUAD_CurrentVersionRun_7925 {
  strings:
    $key_7925 = { 2a 4a [2] 0e 44 [2] 25 68 [2] 0b 4a [2] 1f 51 [2] 10 4b [2] 0e 56 [2] 0c 57 [2] 17 51 [2] 0b 56 [2] 17 79 }

  condition:
    any of them
}