rule TTP_XOR_QUAD_CurrentVersionRun_0172 {
  strings:
    $key_0172 = { 52 1d [2] 76 13 [2] 5d 3f [2] 73 1d [2] 67 06 [2] 68 1c [2] 76 01 [2] 74 00 [2] 6f 06 [2] 73 01 [2] 6f 2e }

  condition:
    any of them
}