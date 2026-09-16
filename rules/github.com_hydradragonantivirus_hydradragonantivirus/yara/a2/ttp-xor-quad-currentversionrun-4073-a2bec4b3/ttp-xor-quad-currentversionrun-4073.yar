rule TTP_XOR_QUAD_CurrentVersionRun_4073 {
  strings:
    $key_4073 = { 13 1c [2] 37 12 [2] 1c 3e [2] 32 1c [2] 26 07 [2] 29 1d [2] 37 00 [2] 35 01 [2] 2e 07 [2] 32 00 [2] 2e 2f }

  condition:
    any of them
}