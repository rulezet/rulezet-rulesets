rule TTP_XOR_QUAD_CurrentVersionRun_315a {
  strings:
    $key_315a = { 62 35 [2] 46 3b [2] 6d 17 [2] 43 35 [2] 57 2e [2] 58 34 [2] 46 29 [2] 44 28 [2] 5f 2e [2] 43 29 [2] 5f 06 }

  condition:
    any of them
}