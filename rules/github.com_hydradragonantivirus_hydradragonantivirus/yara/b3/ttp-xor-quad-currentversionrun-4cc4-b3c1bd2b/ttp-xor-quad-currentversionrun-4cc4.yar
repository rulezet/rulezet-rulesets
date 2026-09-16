rule TTP_XOR_QUAD_CurrentVersionRun_4cc4 {
  strings:
    $key_4cc4 = { 1f ab [2] 3b a5 [2] 10 89 [2] 3e ab [2] 2a b0 [2] 25 aa [2] 3b b7 [2] 39 b6 [2] 22 b0 [2] 3e b7 [2] 22 98 }

  condition:
    any of them
}