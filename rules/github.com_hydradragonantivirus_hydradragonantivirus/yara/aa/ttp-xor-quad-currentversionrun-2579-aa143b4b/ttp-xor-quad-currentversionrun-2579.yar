rule TTP_XOR_QUAD_CurrentVersionRun_2579 {
  strings:
    $key_2579 = { 76 16 [2] 52 18 [2] 79 34 [2] 57 16 [2] 43 0d [2] 4c 17 [2] 52 0a [2] 50 0b [2] 4b 0d [2] 57 0a [2] 4b 25 }

  condition:
    any of them
}