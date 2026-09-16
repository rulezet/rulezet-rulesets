rule TTP_XOR_QUAD_CurrentVersionRun_2436 {
  strings:
    $key_2436 = { 77 59 [2] 53 57 [2] 78 7b [2] 56 59 [2] 42 42 [2] 4d 58 [2] 53 45 [2] 51 44 [2] 4a 42 [2] 56 45 [2] 4a 6a }

  condition:
    any of them
}