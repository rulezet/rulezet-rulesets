rule TTP_XOR_QUAD_CurrentVersionRun_7263 {
  strings:
    $key_7263 = { 21 0c [2] 05 02 [2] 2e 2e [2] 00 0c [2] 14 17 [2] 1b 0d [2] 05 10 [2] 07 11 [2] 1c 17 [2] 00 10 [2] 1c 3f }

  condition:
    any of them
}