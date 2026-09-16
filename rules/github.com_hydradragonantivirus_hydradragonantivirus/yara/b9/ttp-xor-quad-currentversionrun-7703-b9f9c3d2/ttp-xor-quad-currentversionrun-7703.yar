rule TTP_XOR_QUAD_CurrentVersionRun_7703 {
  strings:
    $key_7703 = { 24 6c [2] 00 62 [2] 2b 4e [2] 05 6c [2] 11 77 [2] 1e 6d [2] 00 70 [2] 02 71 [2] 19 77 [2] 05 70 [2] 19 5f }

  condition:
    any of them
}