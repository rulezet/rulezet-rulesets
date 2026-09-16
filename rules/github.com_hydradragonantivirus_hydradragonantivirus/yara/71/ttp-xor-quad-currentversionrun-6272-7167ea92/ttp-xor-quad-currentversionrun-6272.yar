rule TTP_XOR_QUAD_CurrentVersionRun_6272 {
  strings:
    $key_6272 = { 31 1d [2] 15 13 [2] 3e 3f [2] 10 1d [2] 04 06 [2] 0b 1c [2] 15 01 [2] 17 00 [2] 0c 06 [2] 10 01 [2] 0c 2e }

  condition:
    any of them
}