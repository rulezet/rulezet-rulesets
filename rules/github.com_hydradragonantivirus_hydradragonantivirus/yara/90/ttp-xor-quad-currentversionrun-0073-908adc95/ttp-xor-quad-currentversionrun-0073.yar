rule TTP_XOR_QUAD_CurrentVersionRun_0073 {
  strings:
    $key_0073 = { 53 1c [2] 77 12 [2] 5c 3e [2] 72 1c [2] 66 07 [2] 69 1d [2] 77 00 [2] 75 01 [2] 6e 07 [2] 72 00 [2] 6e 2f }

  condition:
    any of them
}