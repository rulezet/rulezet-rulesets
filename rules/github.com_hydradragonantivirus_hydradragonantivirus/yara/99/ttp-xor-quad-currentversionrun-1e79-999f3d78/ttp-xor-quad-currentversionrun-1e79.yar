rule TTP_XOR_QUAD_CurrentVersionRun_1e79 {
  strings:
    $key_1e79 = { 4d 16 [2] 69 18 [2] 42 34 [2] 6c 16 [2] 78 0d [2] 77 17 [2] 69 0a [2] 6b 0b [2] 70 0d [2] 6c 0a [2] 70 25 }

  condition:
    any of them
}