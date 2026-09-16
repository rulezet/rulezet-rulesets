rule TTP_XOR_QUAD_CurrentVersionRun_0f72 {
  strings:
    $key_0f72 = { 5c 1d [2] 78 13 [2] 53 3f [2] 7d 1d [2] 69 06 [2] 66 1c [2] 78 01 [2] 7a 00 [2] 61 06 [2] 7d 01 [2] 61 2e }

  condition:
    any of them
}