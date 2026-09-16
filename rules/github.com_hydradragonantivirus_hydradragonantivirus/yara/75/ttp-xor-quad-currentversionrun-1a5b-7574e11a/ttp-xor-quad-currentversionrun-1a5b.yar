rule TTP_XOR_QUAD_CurrentVersionRun_1a5b {
  strings:
    $key_1a5b = { 49 34 [2] 6d 3a [2] 46 16 [2] 68 34 [2] 7c 2f [2] 73 35 [2] 6d 28 [2] 6f 29 [2] 74 2f [2] 68 28 [2] 74 07 }

  condition:
    any of them
}