rule TTP_XOR_QUAD_CurrentVersionRun_605a {
  strings:
    $key_605a = { 33 35 [2] 17 3b [2] 3c 17 [2] 12 35 [2] 06 2e [2] 09 34 [2] 17 29 [2] 15 28 [2] 0e 2e [2] 12 29 [2] 0e 06 }

  condition:
    any of them
}