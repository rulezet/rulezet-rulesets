rule TTP_XOR_QUAD_CurrentVersionRun_1d72 {
  strings:
    $key_1d72 = { 4e 1d [2] 6a 13 [2] 41 3f [2] 6f 1d [2] 7b 06 [2] 74 1c [2] 6a 01 [2] 68 00 [2] 73 06 [2] 6f 01 [2] 73 2e }

  condition:
    any of them
}