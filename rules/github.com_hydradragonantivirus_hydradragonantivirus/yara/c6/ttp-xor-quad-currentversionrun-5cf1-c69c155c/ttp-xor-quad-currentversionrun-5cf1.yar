rule TTP_XOR_QUAD_CurrentVersionRun_5cf1 {
  strings:
    $key_5cf1 = { 0f 9e [2] 2b 90 [2] 00 bc [2] 2e 9e [2] 3a 85 [2] 35 9f [2] 2b 82 [2] 29 83 [2] 32 85 [2] 2e 82 [2] 32 ad }

  condition:
    any of them
}