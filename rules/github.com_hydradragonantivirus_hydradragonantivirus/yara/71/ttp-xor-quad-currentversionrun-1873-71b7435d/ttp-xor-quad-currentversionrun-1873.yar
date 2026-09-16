rule TTP_XOR_QUAD_CurrentVersionRun_1873 {
  strings:
    $key_1873 = { 4b 1c [2] 6f 12 [2] 44 3e [2] 6a 1c [2] 7e 07 [2] 71 1d [2] 6f 00 [2] 6d 01 [2] 76 07 [2] 6a 00 [2] 76 2f }

  condition:
    any of them
}