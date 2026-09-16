rule TTP_XOR_QUAD_CurrentVersionRun_3604 {
  strings:
    $key_3604 = { 65 6b [2] 41 65 [2] 6a 49 [2] 44 6b [2] 50 70 [2] 5f 6a [2] 41 77 [2] 43 76 [2] 58 70 [2] 44 77 [2] 58 58 }

  condition:
    any of them
}