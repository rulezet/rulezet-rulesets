rule TTP_XOR_QUAD_CurrentVersionRun_4004 {
  strings:
    $key_4004 = { 13 6b [2] 37 65 [2] 1c 49 [2] 32 6b [2] 26 70 [2] 29 6a [2] 37 77 [2] 35 76 [2] 2e 70 [2] 32 77 [2] 2e 58 }

  condition:
    any of them
}