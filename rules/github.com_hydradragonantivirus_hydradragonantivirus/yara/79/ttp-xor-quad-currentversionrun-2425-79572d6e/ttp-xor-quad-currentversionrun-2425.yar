rule TTP_XOR_QUAD_CurrentVersionRun_2425 {
  strings:
    $key_2425 = { 77 4a [2] 53 44 [2] 78 68 [2] 56 4a [2] 42 51 [2] 4d 4b [2] 53 56 [2] 51 57 [2] 4a 51 [2] 56 56 [2] 4a 79 }

  condition:
    any of them
}