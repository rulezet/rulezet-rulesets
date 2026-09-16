rule TTP_XOR_QUAD_CurrentVersionRun_1e24 {
  strings:
    $key_1e24 = { 4d 4b [2] 69 45 [2] 42 69 [2] 6c 4b [2] 78 50 [2] 77 4a [2] 69 57 [2] 6b 56 [2] 70 50 [2] 6c 57 [2] 70 78 }

  condition:
    any of them
}