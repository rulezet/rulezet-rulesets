rule TTP_XOR_QUAD_CurrentVersionRun_6d5a {
  strings:
    $key_6d5a = { 3e 35 [2] 1a 3b [2] 31 17 [2] 1f 35 [2] 0b 2e [2] 04 34 [2] 1a 29 [2] 18 28 [2] 03 2e [2] 1f 29 [2] 03 06 }

  condition:
    any of them
}