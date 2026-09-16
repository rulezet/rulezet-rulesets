rule TTP_XOR_QUAD_CurrentVersionRun_5c02 {
  strings:
    $key_5c02 = { 0f 6d [2] 2b 63 [2] 00 4f [2] 2e 6d [2] 3a 76 [2] 35 6c [2] 2b 71 [2] 29 70 [2] 32 76 [2] 2e 71 [2] 32 5e }

  condition:
    any of them
}