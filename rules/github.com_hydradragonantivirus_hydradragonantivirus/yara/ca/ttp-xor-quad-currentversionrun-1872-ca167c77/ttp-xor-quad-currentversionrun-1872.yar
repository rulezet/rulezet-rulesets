rule TTP_XOR_QUAD_CurrentVersionRun_1872 {
  strings:
    $key_1872 = { 4b 1d [2] 6f 13 [2] 44 3f [2] 6a 1d [2] 7e 06 [2] 71 1c [2] 6f 01 [2] 6d 00 [2] 76 06 [2] 6a 01 [2] 76 2e }

  condition:
    any of them
}