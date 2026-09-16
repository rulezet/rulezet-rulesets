rule TTP_XOR_QUAD_CurrentVersionRun_2565 {
  strings:
    $key_2565 = { 76 0a [2] 52 04 [2] 79 28 [2] 57 0a [2] 43 11 [2] 4c 0b [2] 52 16 [2] 50 17 [2] 4b 11 [2] 57 16 [2] 4b 39 }

  condition:
    any of them
}