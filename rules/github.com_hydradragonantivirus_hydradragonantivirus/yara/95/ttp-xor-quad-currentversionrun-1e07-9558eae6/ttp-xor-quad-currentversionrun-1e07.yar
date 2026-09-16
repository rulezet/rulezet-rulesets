rule TTP_XOR_QUAD_CurrentVersionRun_1e07 {
  strings:
    $key_1e07 = { 4d 68 [2] 69 66 [2] 42 4a [2] 6c 68 [2] 78 73 [2] 77 69 [2] 69 74 [2] 6b 75 [2] 70 73 [2] 6c 74 [2] 70 5b }

  condition:
    any of them
}