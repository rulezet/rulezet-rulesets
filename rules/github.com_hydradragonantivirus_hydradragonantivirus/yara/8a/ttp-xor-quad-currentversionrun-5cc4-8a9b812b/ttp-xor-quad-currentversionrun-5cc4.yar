rule TTP_XOR_QUAD_CurrentVersionRun_5cc4 {
  strings:
    $key_5cc4 = { 0f ab [2] 2b a5 [2] 00 89 [2] 2e ab [2] 3a b0 [2] 35 aa [2] 2b b7 [2] 29 b6 [2] 32 b0 [2] 2e b7 [2] 32 98 }

  condition:
    any of them
}