rule TTP_XOR_QUAD_CurrentVersionRun_40e4 {
  strings:
    $key_40e4 = { 13 8b [2] 37 85 [2] 1c a9 [2] 32 8b [2] 26 90 [2] 29 8a [2] 37 97 [2] 35 96 [2] 2e 90 [2] 32 97 [2] 2e b8 }

  condition:
    any of them
}