rule TTP_XOR_QUAD_CurrentVersionRun_3c36 {
  strings:
    $key_3c36 = { 6f 59 [2] 4b 57 [2] 60 7b [2] 4e 59 [2] 5a 42 [2] 55 58 [2] 4b 45 [2] 49 44 [2] 52 42 [2] 4e 45 [2] 52 6a }

  condition:
    any of them
}