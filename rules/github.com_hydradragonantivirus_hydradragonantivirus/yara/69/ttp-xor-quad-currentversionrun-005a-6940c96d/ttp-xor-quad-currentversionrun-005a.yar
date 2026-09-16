rule TTP_XOR_QUAD_CurrentVersionRun_005a {
  strings:
    $key_005a = { 53 35 [2] 77 3b [2] 5c 17 [2] 72 35 [2] 66 2e [2] 69 34 [2] 77 29 [2] 75 28 [2] 6e 2e [2] 72 29 [2] 6e 06 }

  condition:
    any of them
}