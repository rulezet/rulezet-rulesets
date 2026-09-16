rule TTP_XOR_QUAD_CurrentVersionRun_6536 {
  strings:
    $key_6536 = { 36 59 [2] 12 57 [2] 39 7b [2] 17 59 [2] 03 42 [2] 0c 58 [2] 12 45 [2] 10 44 [2] 0b 42 [2] 17 45 [2] 0b 6a }

  condition:
    any of them
}