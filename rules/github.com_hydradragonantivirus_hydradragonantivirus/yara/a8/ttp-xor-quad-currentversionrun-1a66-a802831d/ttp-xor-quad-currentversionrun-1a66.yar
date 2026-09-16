rule TTP_XOR_QUAD_CurrentVersionRun_1a66 {
  strings:
    $key_1a66 = { 49 09 [2] 6d 07 [2] 46 2b [2] 68 09 [2] 7c 12 [2] 73 08 [2] 6d 15 [2] 6f 14 [2] 74 12 [2] 68 15 [2] 74 3a }

  condition:
    any of them
}