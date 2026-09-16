rule TTP_XOR_QUAD_CurrentVersionRun_685a {
  strings:
    $key_685a = { 3b 35 [2] 1f 3b [2] 34 17 [2] 1a 35 [2] 0e 2e [2] 01 34 [2] 1f 29 [2] 1d 28 [2] 06 2e [2] 1a 29 [2] 06 06 }

  condition:
    any of them
}