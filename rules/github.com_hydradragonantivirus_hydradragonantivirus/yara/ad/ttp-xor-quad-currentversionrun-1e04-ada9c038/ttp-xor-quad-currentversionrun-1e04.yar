rule TTP_XOR_QUAD_CurrentVersionRun_1e04 {
  strings:
    $key_1e04 = { 4d 6b [2] 69 65 [2] 42 49 [2] 6c 6b [2] 78 70 [2] 77 6a [2] 69 77 [2] 6b 76 [2] 70 70 [2] 6c 77 [2] 70 58 }

  condition:
    any of them
}