rule TTP_XOR_QUAD_CurrentVersionRun_5c31 {
  strings:
    $key_5c31 = { 0f 5e [2] 2b 50 [2] 00 7c [2] 2e 5e [2] 3a 45 [2] 35 5f [2] 2b 42 [2] 29 43 [2] 32 45 [2] 2e 42 [2] 32 6d }

  condition:
    any of them
}