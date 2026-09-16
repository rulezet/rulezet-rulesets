rule TTP_XOR_QUAD_CurrentVersionRun_1e1b {
  strings:
    $key_1e1b = { 4d 74 [2] 69 7a [2] 42 56 [2] 6c 74 [2] 78 6f [2] 77 75 [2] 69 68 [2] 6b 69 [2] 70 6f [2] 6c 68 [2] 70 47 }

  condition:
    any of them
}