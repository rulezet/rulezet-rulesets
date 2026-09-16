rule TTP_XOR_QUAD_CurrentVersionRun_00e4 {
  strings:
    $key_00e4 = { 53 8b [2] 77 85 [2] 5c a9 [2] 72 8b [2] 66 90 [2] 69 8a [2] 77 97 [2] 75 96 [2] 6e 90 [2] 72 97 [2] 6e b8 }

  condition:
    any of them
}