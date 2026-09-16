rule TTP_XOR_QUAD_CurrentVersionRun_1e55 {
  strings:
    $key_1e55 = { 4d 3a [2] 69 34 [2] 42 18 [2] 6c 3a [2] 78 21 [2] 77 3b [2] 69 26 [2] 6b 27 [2] 70 21 [2] 6c 26 [2] 70 09 }

  condition:
    any of them
}