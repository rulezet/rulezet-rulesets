rule TTP_XOR_QUAD_CurrentVersionRun_773a {
  strings:
    $key_773a = { 24 55 [2] 00 5b [2] 2b 77 [2] 05 55 [2] 11 4e [2] 1e 54 [2] 00 49 [2] 02 48 [2] 19 4e [2] 05 49 [2] 19 66 }

  condition:
    any of them
}