rule TTP_XOR_QUAD_CurrentVersionRun_2479 {
  strings:
    $key_2479 = { 77 16 [2] 53 18 [2] 78 34 [2] 56 16 [2] 42 0d [2] 4d 17 [2] 53 0a [2] 51 0b [2] 4a 0d [2] 56 0a [2] 4a 25 }

  condition:
    any of them
}