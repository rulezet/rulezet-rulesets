rule TTP_XOR_QUAD_CurrentVersionRun_5c34 {
  strings:
    $key_5c34 = { 0f 5b [2] 2b 55 [2] 00 79 [2] 2e 5b [2] 3a 40 [2] 35 5a [2] 2b 47 [2] 29 46 [2] 32 40 [2] 2e 47 [2] 32 68 }

  condition:
    any of them
}