rule TTP_XOR_QUAD_CurrentVersionRun_1d5a {
  strings:
    $key_1d5a = { 4e 35 [2] 6a 3b [2] 41 17 [2] 6f 35 [2] 7b 2e [2] 74 34 [2] 6a 29 [2] 68 28 [2] 73 2e [2] 6f 29 [2] 73 06 }

  condition:
    any of them
}