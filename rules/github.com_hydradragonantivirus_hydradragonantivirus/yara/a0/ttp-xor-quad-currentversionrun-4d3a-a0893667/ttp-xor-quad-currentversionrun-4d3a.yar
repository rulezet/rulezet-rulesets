rule TTP_XOR_QUAD_CurrentVersionRun_4d3a {
  strings:
    $key_4d3a = { 1e 55 [2] 3a 5b [2] 11 77 [2] 3f 55 [2] 2b 4e [2] 24 54 [2] 3a 49 [2] 38 48 [2] 23 4e [2] 3f 49 [2] 23 66 }

  condition:
    any of them
}