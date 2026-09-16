rule TTP_XOR_QUAD_CurrentVersionRun_0063 {
  strings:
    $key_0063 = { 53 0c [2] 77 02 [2] 5c 2e [2] 72 0c [2] 66 17 [2] 69 0d [2] 77 10 [2] 75 11 [2] 6e 17 [2] 72 10 [2] 6e 3f }

  condition:
    any of them
}