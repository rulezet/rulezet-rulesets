rule TTP_XOR_QUAD_CurrentVersionRun_3372 {
  strings:
    $key_3372 = { 60 1d [2] 44 13 [2] 6f 3f [2] 41 1d [2] 55 06 [2] 5a 1c [2] 44 01 [2] 46 00 [2] 5d 06 [2] 41 01 [2] 5d 2e }

  condition:
    any of them
}