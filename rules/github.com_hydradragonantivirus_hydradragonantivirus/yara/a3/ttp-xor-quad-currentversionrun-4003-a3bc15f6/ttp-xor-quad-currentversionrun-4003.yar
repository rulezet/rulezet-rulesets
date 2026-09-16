rule TTP_XOR_QUAD_CurrentVersionRun_4003 {
  strings:
    $key_4003 = { 13 6c [2] 37 62 [2] 1c 4e [2] 32 6c [2] 26 77 [2] 29 6d [2] 37 70 [2] 35 71 [2] 2e 77 [2] 32 70 [2] 2e 5f }

  condition:
    any of them
}