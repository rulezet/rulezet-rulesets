rule TTP_XOR_QUAD_CurrentVersionRun_2406 {
  strings:
    $key_2406 = { 77 69 [2] 53 67 [2] 78 4b [2] 56 69 [2] 42 72 [2] 4d 68 [2] 53 75 [2] 51 74 [2] 4a 72 [2] 56 75 [2] 4a 5a }

  condition:
    any of them
}