rule TTP_XOR_QUAD_CurrentVersionRun_524a {
  strings:
    $key_524a = { 01 25 [2] 25 2b [2] 0e 07 [2] 20 25 [2] 34 3e [2] 3b 24 [2] 25 39 [2] 27 38 [2] 3c 3e [2] 20 39 [2] 3c 16 }

  condition:
    any of them
}