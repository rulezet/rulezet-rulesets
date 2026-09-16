rule TTP_XOR_QUAD_CurrentVersionRun_285a {
  strings:
    $key_285a = { 7b 35 [2] 5f 3b [2] 74 17 [2] 5a 35 [2] 4e 2e [2] 41 34 [2] 5f 29 [2] 5d 28 [2] 46 2e [2] 5a 29 [2] 46 06 }

  condition:
    any of them
}