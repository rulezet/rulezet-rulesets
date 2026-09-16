rule TTP_XOR_QUAD_CurrentVersionRun_0462 {
  strings:
    $key_0462 = { 57 0d [2] 73 03 [2] 58 2f [2] 76 0d [2] 62 16 [2] 6d 0c [2] 73 11 [2] 71 10 [2] 6a 16 [2] 76 11 [2] 6a 3e }

  condition:
    any of them
}