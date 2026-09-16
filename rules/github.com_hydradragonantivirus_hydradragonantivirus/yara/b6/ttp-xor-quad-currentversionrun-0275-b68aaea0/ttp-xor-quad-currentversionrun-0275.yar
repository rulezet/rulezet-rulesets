rule TTP_XOR_QUAD_CurrentVersionRun_0275 {
  strings:
    $key_0275 = { 51 1a [2] 75 14 [2] 5e 38 [2] 70 1a [2] 64 01 [2] 6b 1b [2] 75 06 [2] 77 07 [2] 6c 01 [2] 70 06 [2] 6c 29 }

  condition:
    any of them
}