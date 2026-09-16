rule TTP_XOR_QUAD_CurrentVersionRun_2d5a {
  strings:
    $key_2d5a = { 7e 35 [2] 5a 3b [2] 71 17 [2] 5f 35 [2] 4b 2e [2] 44 34 [2] 5a 29 [2] 58 28 [2] 43 2e [2] 5f 29 [2] 43 06 }

  condition:
    any of them
}