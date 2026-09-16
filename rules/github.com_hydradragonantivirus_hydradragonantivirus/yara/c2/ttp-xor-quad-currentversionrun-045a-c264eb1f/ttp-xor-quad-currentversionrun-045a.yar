rule TTP_XOR_QUAD_CurrentVersionRun_045a {
  strings:
    $key_045a = { 57 35 [2] 73 3b [2] 58 17 [2] 76 35 [2] 62 2e [2] 6d 34 [2] 73 29 [2] 71 28 [2] 6a 2e [2] 76 29 [2] 6a 06 }

  condition:
    any of them
}