rule TTP_XOR_QUAD_CurrentVersionRun_7a36 {
  strings:
    $key_7a36 = { 29 59 [2] 0d 57 [2] 26 7b [2] 08 59 [2] 1c 42 [2] 13 58 [2] 0d 45 [2] 0f 44 [2] 14 42 [2] 08 45 [2] 14 6a }

  condition:
    any of them
}