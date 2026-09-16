rule TTP_XOR_QUAD_CurrentVersionRun_6d72 {
  strings:
    $key_6d72 = { 3e 1d [2] 1a 13 [2] 31 3f [2] 1f 1d [2] 0b 06 [2] 04 1c [2] 1a 01 [2] 18 00 [2] 03 06 [2] 1f 01 [2] 03 2e }

  condition:
    any of them
}