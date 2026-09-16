rule TTP_XOR_QUAD_CurrentVersionRun_025a {
  strings:
    $key_025a = { 51 35 [2] 75 3b [2] 5e 17 [2] 70 35 [2] 64 2e [2] 6b 34 [2] 75 29 [2] 77 28 [2] 6c 2e [2] 70 29 [2] 6c 06 }

  condition:
    any of them
}