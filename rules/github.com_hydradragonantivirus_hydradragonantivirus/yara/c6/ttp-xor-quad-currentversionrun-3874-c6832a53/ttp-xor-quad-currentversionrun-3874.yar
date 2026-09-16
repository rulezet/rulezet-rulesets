rule TTP_XOR_QUAD_CurrentVersionRun_3874 {
  strings:
    $key_3874 = { 6b 1b [2] 4f 15 [2] 64 39 [2] 4a 1b [2] 5e 00 [2] 51 1a [2] 4f 07 [2] 4d 06 [2] 56 00 [2] 4a 07 [2] 56 28 }

  condition:
    any of them
}