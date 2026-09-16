rule TTP_XOR_QUAD_CurrentVersionRun_5cf6 {
  strings:
    $key_5cf6 = { 0f 99 [2] 2b 97 [2] 00 bb [2] 2e 99 [2] 3a 82 [2] 35 98 [2] 2b 85 [2] 29 84 [2] 32 82 [2] 2e 85 [2] 32 aa }

  condition:
    any of them
}