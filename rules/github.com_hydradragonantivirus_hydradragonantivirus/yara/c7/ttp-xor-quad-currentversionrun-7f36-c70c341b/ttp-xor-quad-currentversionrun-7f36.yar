rule TTP_XOR_QUAD_CurrentVersionRun_7f36 {
  strings:
    $key_7f36 = { 2c 59 [2] 08 57 [2] 23 7b [2] 0d 59 [2] 19 42 [2] 16 58 [2] 08 45 [2] 0a 44 [2] 11 42 [2] 0d 45 [2] 11 6a }

  condition:
    any of them
}