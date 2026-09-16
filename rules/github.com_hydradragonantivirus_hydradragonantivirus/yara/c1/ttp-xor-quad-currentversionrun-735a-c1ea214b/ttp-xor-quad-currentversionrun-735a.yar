rule TTP_XOR_QUAD_CurrentVersionRun_735a {
  strings:
    $key_735a = { 20 35 [2] 04 3b [2] 2f 17 [2] 01 35 [2] 15 2e [2] 1a 34 [2] 04 29 [2] 06 28 [2] 1d 2e [2] 01 29 [2] 1d 06 }

  condition:
    any of them
}