rule TTP_XOR_QUAD_CurrentVersionRun_2467 {
  strings:
    $key_2467 = { 77 08 [2] 53 06 [2] 78 2a [2] 56 08 [2] 42 13 [2] 4d 09 [2] 53 14 [2] 51 15 [2] 4a 13 [2] 56 14 [2] 4a 3b }

  condition:
    any of them
}