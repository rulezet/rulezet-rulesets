rule TTP_XOR_QUAD_CurrentVersionRun_7d3a {
  strings:
    $key_7d3a = { 2e 55 [2] 0a 5b [2] 21 77 [2] 0f 55 [2] 1b 4e [2] 14 54 [2] 0a 49 [2] 08 48 [2] 13 4e [2] 0f 49 [2] 13 66 }

  condition:
    any of them
}