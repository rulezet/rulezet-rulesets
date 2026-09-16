rule TTP_XOR_QUAD_CurrentVersionRun_0a72 {
  strings:
    $key_0a72 = { 59 1d [2] 7d 13 [2] 56 3f [2] 78 1d [2] 6c 06 [2] 63 1c [2] 7d 01 [2] 7f 00 [2] 64 06 [2] 78 01 [2] 64 2e }

  condition:
    any of them
}