rule TTP_XOR_QUAD_CurrentVersionRun_555a {
  strings:
    $key_555a = { 06 35 [2] 22 3b [2] 09 17 [2] 27 35 [2] 33 2e [2] 3c 34 [2] 22 29 [2] 20 28 [2] 3b 2e [2] 27 29 [2] 3b 06 }

  condition:
    any of them
}