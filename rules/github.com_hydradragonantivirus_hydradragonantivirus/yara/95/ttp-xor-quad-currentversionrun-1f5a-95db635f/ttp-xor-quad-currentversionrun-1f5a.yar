rule TTP_XOR_QUAD_CurrentVersionRun_1f5a {
  strings:
    $key_1f5a = { 4c 35 [2] 68 3b [2] 43 17 [2] 6d 35 [2] 79 2e [2] 76 34 [2] 68 29 [2] 6a 28 [2] 71 2e [2] 6d 29 [2] 71 06 }

  condition:
    any of them
}