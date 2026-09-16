rule TTP_XOR_QUAD_CurrentVersionRun_2073 {
  strings:
    $key_2073 = { 73 1c [2] 57 12 [2] 7c 3e [2] 52 1c [2] 46 07 [2] 49 1d [2] 57 00 [2] 55 01 [2] 4e 07 [2] 52 00 [2] 4e 2f }

  condition:
    any of them
}