rule TTP_XOR_QUAD_CurrentVersionRun_5c3a {
  strings:
    $key_5c3a = { 0f 55 [2] 2b 5b [2] 00 77 [2] 2e 55 [2] 3a 4e [2] 35 54 [2] 2b 49 [2] 29 48 [2] 32 4e [2] 2e 49 [2] 32 66 }

  condition:
    any of them
}