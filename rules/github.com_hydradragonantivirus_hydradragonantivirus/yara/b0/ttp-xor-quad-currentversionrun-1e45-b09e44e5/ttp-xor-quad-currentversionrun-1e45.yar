rule TTP_XOR_QUAD_CurrentVersionRun_1e45 {
  strings:
    $key_1e45 = { 4d 2a [2] 69 24 [2] 42 08 [2] 6c 2a [2] 78 31 [2] 77 2b [2] 69 36 [2] 6b 37 [2] 70 31 [2] 6c 36 [2] 70 19 }

  condition:
    any of them
}