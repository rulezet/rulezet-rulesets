rule TTP_XOR_QUAD_CurrentVersionRun_0466 {
  strings:
    $key_0466 = { 57 09 [2] 73 07 [2] 58 2b [2] 76 09 [2] 62 12 [2] 6d 08 [2] 73 15 [2] 71 14 [2] 6a 12 [2] 76 15 [2] 6a 3a }

  condition:
    any of them
}