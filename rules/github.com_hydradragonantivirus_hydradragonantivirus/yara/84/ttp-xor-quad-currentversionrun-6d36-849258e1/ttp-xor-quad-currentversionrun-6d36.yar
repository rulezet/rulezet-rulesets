rule TTP_XOR_QUAD_CurrentVersionRun_6d36 {
  strings:
    $key_6d36 = { 3e 59 [2] 1a 57 [2] 31 7b [2] 1f 59 [2] 0b 42 [2] 04 58 [2] 1a 45 [2] 18 44 [2] 03 42 [2] 1f 45 [2] 03 6a }

  condition:
    any of them
}