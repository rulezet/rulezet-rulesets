rule TTP_XOR_QUAD_CurrentVersionRun_5c26 {
  strings:
    $key_5c26 = { 0f 49 [2] 2b 47 [2] 00 6b [2] 2e 49 [2] 3a 52 [2] 35 48 [2] 2b 55 [2] 29 54 [2] 32 52 [2] 2e 55 [2] 32 7a }

  condition:
    any of them
}