rule TTP_XOR_QUAD_CurrentVersionRun_6036 {
  strings:
    $key_6036 = { 33 59 [2] 17 57 [2] 3c 7b [2] 12 59 [2] 06 42 [2] 09 58 [2] 17 45 [2] 15 44 [2] 0e 42 [2] 12 45 [2] 0e 6a }

  condition:
    any of them
}