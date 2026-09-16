rule TTP_XOR_QUAD_CurrentVersionRun_6666 {
  strings:
    $key_6666 = { 35 09 [2] 11 07 [2] 3a 2b [2] 14 09 [2] 00 12 [2] 0f 08 [2] 11 15 [2] 13 14 [2] 08 12 [2] 14 15 [2] 08 3a }

  condition:
    any of them
}