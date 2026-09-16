rule TTP_XOR_QUAD_CurrentVersionRun_1a72 {
  strings:
    $key_1a72 = { 49 1d [2] 6d 13 [2] 46 3f [2] 68 1d [2] 7c 06 [2] 73 1c [2] 6d 01 [2] 6f 00 [2] 74 06 [2] 68 01 [2] 74 2e }

  condition:
    any of them
}