rule TTP_XOR_QUAD_CurrentVersionRun_5c71 {
  strings:
    $key_5c71 = { 0f 1e [2] 2b 10 [2] 00 3c [2] 2e 1e [2] 3a 05 [2] 35 1f [2] 2b 02 [2] 29 03 [2] 32 05 [2] 2e 02 [2] 32 2d }

  condition:
    any of them
}