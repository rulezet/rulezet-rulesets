rule TTP_XOR_QUAD_CurrentVersionRun_3272 {
  strings:
    $key_3272 = { 61 1d [2] 45 13 [2] 6e 3f [2] 40 1d [2] 54 06 [2] 5b 1c [2] 45 01 [2] 47 00 [2] 5c 06 [2] 40 01 [2] 5c 2e }

  condition:
    any of them
}