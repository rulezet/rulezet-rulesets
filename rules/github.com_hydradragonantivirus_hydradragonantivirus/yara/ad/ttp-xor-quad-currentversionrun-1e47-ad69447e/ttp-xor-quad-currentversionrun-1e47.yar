rule TTP_XOR_QUAD_CurrentVersionRun_1e47 {
  strings:
    $key_1e47 = { 4d 28 [2] 69 26 [2] 42 0a [2] 6c 28 [2] 78 33 [2] 77 29 [2] 69 34 [2] 6b 35 [2] 70 33 [2] 6c 34 [2] 70 1b }

  condition:
    any of them
}