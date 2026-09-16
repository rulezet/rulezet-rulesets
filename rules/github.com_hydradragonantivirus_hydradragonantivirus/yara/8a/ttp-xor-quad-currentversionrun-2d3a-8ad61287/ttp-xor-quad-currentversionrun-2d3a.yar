rule TTP_XOR_QUAD_CurrentVersionRun_2d3a {
  strings:
    $key_2d3a = { 7e 55 [2] 5a 5b [2] 71 77 [2] 5f 55 [2] 4b 4e [2] 44 54 [2] 5a 49 [2] 58 48 [2] 43 4e [2] 5f 49 [2] 43 66 }

  condition:
    any of them
}