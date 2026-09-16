rule TTP_XOR_QUAD_CurrentVersionRun_1b5a {
  strings:
    $key_1b5a = { 48 35 [2] 6c 3b [2] 47 17 [2] 69 35 [2] 7d 2e [2] 72 34 [2] 6c 29 [2] 6e 28 [2] 75 2e [2] 69 29 [2] 75 06 }

  condition:
    any of them
}