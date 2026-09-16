rule TTP_XOR_QUAD_CurrentVersionRun_4e36 {
  strings:
    $key_4e36 = { 1d 59 [2] 39 57 [2] 12 7b [2] 3c 59 [2] 28 42 [2] 27 58 [2] 39 45 [2] 3b 44 [2] 20 42 [2] 3c 45 [2] 20 6a }

  condition:
    any of them
}