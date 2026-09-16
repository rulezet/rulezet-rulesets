rule TTP_XOR_QUAD_CurrentVersionRun_3c72 {
  strings:
    $key_3c72 = { 6f 1d [2] 4b 13 [2] 60 3f [2] 4e 1d [2] 5a 06 [2] 55 1c [2] 4b 01 [2] 49 00 [2] 52 06 [2] 4e 01 [2] 52 2e }

  condition:
    any of them
}