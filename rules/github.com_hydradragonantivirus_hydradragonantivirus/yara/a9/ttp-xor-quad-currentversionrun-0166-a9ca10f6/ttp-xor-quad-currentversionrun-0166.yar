rule TTP_XOR_QUAD_CurrentVersionRun_0166 {
  strings:
    $key_0166 = { 52 09 [2] 76 07 [2] 5d 2b [2] 73 09 [2] 67 12 [2] 68 08 [2] 76 15 [2] 74 14 [2] 6f 12 [2] 73 15 [2] 6f 3a }

  condition:
    any of them
}