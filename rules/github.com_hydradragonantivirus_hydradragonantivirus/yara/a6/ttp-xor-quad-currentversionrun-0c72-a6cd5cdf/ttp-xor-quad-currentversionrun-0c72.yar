rule TTP_XOR_QUAD_CurrentVersionRun_0c72 {
  strings:
    $key_0c72 = { 5f 1d [2] 7b 13 [2] 50 3f [2] 7e 1d [2] 6a 06 [2] 65 1c [2] 7b 01 [2] 79 00 [2] 62 06 [2] 7e 01 [2] 62 2e }

  condition:
    any of them
}