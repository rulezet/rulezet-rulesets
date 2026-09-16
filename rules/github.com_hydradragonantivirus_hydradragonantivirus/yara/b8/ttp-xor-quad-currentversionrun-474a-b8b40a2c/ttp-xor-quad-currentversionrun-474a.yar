rule TTP_XOR_QUAD_CurrentVersionRun_474a {
  strings:
    $key_474a = { 14 25 [2] 30 2b [2] 1b 07 [2] 35 25 [2] 21 3e [2] 2e 24 [2] 30 39 [2] 32 38 [2] 29 3e [2] 35 39 [2] 29 16 }

  condition:
    any of them
}