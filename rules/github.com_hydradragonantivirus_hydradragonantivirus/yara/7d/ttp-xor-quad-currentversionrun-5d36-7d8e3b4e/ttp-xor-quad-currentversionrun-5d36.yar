rule TTP_XOR_QUAD_CurrentVersionRun_5d36 {
  strings:
    $key_5d36 = { 0e 59 [2] 2a 57 [2] 01 7b [2] 2f 59 [2] 3b 42 [2] 34 58 [2] 2a 45 [2] 28 44 [2] 33 42 [2] 2f 45 [2] 33 6a }

  condition:
    any of them
}