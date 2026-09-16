rule TTP_XOR_QUAD_CurrentVersionRun_795a {
  strings:
    $key_795a = { 2a 35 [2] 0e 3b [2] 25 17 [2] 0b 35 [2] 1f 2e [2] 10 34 [2] 0e 29 [2] 0c 28 [2] 17 2e [2] 0b 29 [2] 17 06 }

  condition:
    any of them
}