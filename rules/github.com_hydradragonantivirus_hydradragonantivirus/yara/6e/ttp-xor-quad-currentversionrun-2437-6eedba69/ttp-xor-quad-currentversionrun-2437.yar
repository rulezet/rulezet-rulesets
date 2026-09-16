rule TTP_XOR_QUAD_CurrentVersionRun_2437 {
  strings:
    $key_2437 = { 77 58 [2] 53 56 [2] 78 7a [2] 56 58 [2] 42 43 [2] 4d 59 [2] 53 44 [2] 51 45 [2] 4a 43 [2] 56 44 [2] 4a 6b }

  condition:
    any of them
}