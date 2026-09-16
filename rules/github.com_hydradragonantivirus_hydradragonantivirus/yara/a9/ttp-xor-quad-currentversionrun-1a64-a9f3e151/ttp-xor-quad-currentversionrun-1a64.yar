rule TTP_XOR_QUAD_CurrentVersionRun_1a64 {
  strings:
    $key_1a64 = { 49 0b [2] 6d 05 [2] 46 29 [2] 68 0b [2] 7c 10 [2] 73 0a [2] 6d 17 [2] 6f 16 [2] 74 10 [2] 68 17 [2] 74 38 }

  condition:
    any of them
}