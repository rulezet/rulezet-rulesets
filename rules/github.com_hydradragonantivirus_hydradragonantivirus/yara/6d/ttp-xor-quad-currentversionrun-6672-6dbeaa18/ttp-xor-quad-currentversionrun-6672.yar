rule TTP_XOR_QUAD_CurrentVersionRun_6672 {
  strings:
    $key_6672 = { 35 1d [2] 11 13 [2] 3a 3f [2] 14 1d [2] 00 06 [2] 0f 1c [2] 11 01 [2] 13 00 [2] 08 06 [2] 14 01 [2] 08 2e }

  condition:
    any of them
}