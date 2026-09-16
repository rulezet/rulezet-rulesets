rule TTP_XOR_QUAD_CurrentVersionRun_5c27 {
  strings:
    $key_5c27 = { 0f 48 [2] 2b 46 [2] 00 6a [2] 2e 48 [2] 3a 53 [2] 35 49 [2] 2b 54 [2] 29 55 [2] 32 53 [2] 2e 54 [2] 32 7b }

  condition:
    any of them
}