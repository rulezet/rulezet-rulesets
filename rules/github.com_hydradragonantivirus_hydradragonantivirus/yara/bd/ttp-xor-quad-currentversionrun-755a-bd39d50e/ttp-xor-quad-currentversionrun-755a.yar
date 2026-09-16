rule TTP_XOR_QUAD_CurrentVersionRun_755a {
  strings:
    $key_755a = { 26 35 [2] 02 3b [2] 29 17 [2] 07 35 [2] 13 2e [2] 1c 34 [2] 02 29 [2] 00 28 [2] 1b 2e [2] 07 29 [2] 1b 06 }

  condition:
    any of them
}