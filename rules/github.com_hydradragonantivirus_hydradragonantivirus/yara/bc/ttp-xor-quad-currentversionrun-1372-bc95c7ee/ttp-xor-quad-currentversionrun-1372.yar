rule TTP_XOR_QUAD_CurrentVersionRun_1372 {
  strings:
    $key_1372 = { 40 1d [2] 64 13 [2] 4f 3f [2] 61 1d [2] 75 06 [2] 7a 1c [2] 64 01 [2] 66 00 [2] 7d 06 [2] 61 01 [2] 7d 2e }

  condition:
    any of them
}