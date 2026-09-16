rule TTP_XOR_QUAD_CurrentVersionRun_0f73 {
  strings:
    $key_0f73 = { 5c 1c [2] 78 12 [2] 53 3e [2] 7d 1c [2] 69 07 [2] 66 1d [2] 78 00 [2] 7a 01 [2] 61 07 [2] 7d 00 [2] 61 2f }

  condition:
    any of them
}