rule TTP_XOR_QUAD_CurrentVersionRun_0b5a {
  strings:
    $key_0b5a = { 58 35 [2] 7c 3b [2] 57 17 [2] 79 35 [2] 6d 2e [2] 62 34 [2] 7c 29 [2] 7e 28 [2] 65 2e [2] 79 29 [2] 65 06 }

  condition:
    any of them
}