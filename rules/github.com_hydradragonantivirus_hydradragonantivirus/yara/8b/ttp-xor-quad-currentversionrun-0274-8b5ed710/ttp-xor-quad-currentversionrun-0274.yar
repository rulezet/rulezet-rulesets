rule TTP_XOR_QUAD_CurrentVersionRun_0274 {
  strings:
    $key_0274 = { 51 1b [2] 75 15 [2] 5e 39 [2] 70 1b [2] 64 00 [2] 6b 1a [2] 75 07 [2] 77 06 [2] 6c 00 [2] 70 07 [2] 6c 28 }

  condition:
    any of them
}