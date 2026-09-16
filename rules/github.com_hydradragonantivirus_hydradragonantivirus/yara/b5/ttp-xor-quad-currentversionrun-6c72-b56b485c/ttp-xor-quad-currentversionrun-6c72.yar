rule TTP_XOR_QUAD_CurrentVersionRun_6c72 {
  strings:
    $key_6c72 = { 3f 1d [2] 1b 13 [2] 30 3f [2] 1e 1d [2] 0a 06 [2] 05 1c [2] 1b 01 [2] 19 00 [2] 02 06 [2] 1e 01 [2] 02 2e }

  condition:
    any of them
}