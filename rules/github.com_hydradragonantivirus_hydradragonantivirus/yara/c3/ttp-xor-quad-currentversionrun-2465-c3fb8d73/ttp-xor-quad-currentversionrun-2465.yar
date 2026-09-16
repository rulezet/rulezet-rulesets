rule TTP_XOR_QUAD_CurrentVersionRun_2465 {
  strings:
    $key_2465 = { 77 0a [2] 53 04 [2] 78 28 [2] 56 0a [2] 42 11 [2] 4d 0b [2] 53 16 [2] 51 17 [2] 4a 11 [2] 56 16 [2] 4a 39 }

  condition:
    any of them
}