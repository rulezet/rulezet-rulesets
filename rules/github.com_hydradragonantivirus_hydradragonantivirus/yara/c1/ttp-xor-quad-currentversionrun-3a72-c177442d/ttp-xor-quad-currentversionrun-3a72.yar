rule TTP_XOR_QUAD_CurrentVersionRun_3a72 {
  strings:
    $key_3a72 = { 69 1d [2] 4d 13 [2] 66 3f [2] 48 1d [2] 5c 06 [2] 53 1c [2] 4d 01 [2] 4f 00 [2] 54 06 [2] 48 01 [2] 54 2e }

  condition:
    any of them
}