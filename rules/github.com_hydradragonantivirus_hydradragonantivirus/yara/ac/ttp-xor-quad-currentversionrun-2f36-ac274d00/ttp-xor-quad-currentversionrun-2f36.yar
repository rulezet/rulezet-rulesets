rule TTP_XOR_QUAD_CurrentVersionRun_2f36 {
  strings:
    $key_2f36 = { 7c 59 [2] 58 57 [2] 73 7b [2] 5d 59 [2] 49 42 [2] 46 58 [2] 58 45 [2] 5a 44 [2] 41 42 [2] 5d 45 [2] 41 6a }

  condition:
    any of them
}