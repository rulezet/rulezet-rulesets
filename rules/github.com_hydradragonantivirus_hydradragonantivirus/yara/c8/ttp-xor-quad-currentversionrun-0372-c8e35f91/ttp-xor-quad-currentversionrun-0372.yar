rule TTP_XOR_QUAD_CurrentVersionRun_0372 {
  strings:
    $key_0372 = { 50 1d [2] 74 13 [2] 5f 3f [2] 71 1d [2] 65 06 [2] 6a 1c [2] 74 01 [2] 76 00 [2] 6d 06 [2] 71 01 [2] 6d 2e }

  condition:
    any of them
}