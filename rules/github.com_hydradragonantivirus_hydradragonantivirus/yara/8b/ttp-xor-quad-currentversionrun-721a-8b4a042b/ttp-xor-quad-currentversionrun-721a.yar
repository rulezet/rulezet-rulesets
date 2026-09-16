rule TTP_XOR_QUAD_CurrentVersionRun_721a {
  strings:
    $key_721a = { 21 75 [2] 05 7b [2] 2e 57 [2] 00 75 [2] 14 6e [2] 1b 74 [2] 05 69 [2] 07 68 [2] 1c 6e [2] 00 69 [2] 1c 46 }

  condition:
    any of them
}