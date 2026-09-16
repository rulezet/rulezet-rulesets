rule TTP_XOR_QUAD_CurrentVersionRun_5c32 {
  strings:
    $key_5c32 = { 0f 5d [2] 2b 53 [2] 00 7f [2] 2e 5d [2] 3a 46 [2] 35 5c [2] 2b 41 [2] 29 40 [2] 32 46 [2] 2e 41 [2] 32 6e }

  condition:
    any of them
}