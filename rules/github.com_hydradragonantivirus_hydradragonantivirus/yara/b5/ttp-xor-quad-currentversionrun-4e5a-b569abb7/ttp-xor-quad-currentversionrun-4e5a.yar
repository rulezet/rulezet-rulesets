rule TTP_XOR_QUAD_CurrentVersionRun_4e5a {
  strings:
    $key_4e5a = { 1d 35 [2] 39 3b [2] 12 17 [2] 3c 35 [2] 28 2e [2] 27 34 [2] 39 29 [2] 3b 28 [2] 20 2e [2] 3c 29 [2] 20 06 }

  condition:
    any of them
}