rule TTP_XOR_QUAD_CurrentVersionRun_0c36 {
  strings:
    $key_0c36 = { 5f 59 [2] 7b 57 [2] 50 7b [2] 7e 59 [2] 6a 42 [2] 65 58 [2] 7b 45 [2] 79 44 [2] 62 42 [2] 7e 45 [2] 62 6a }

  condition:
    any of them
}