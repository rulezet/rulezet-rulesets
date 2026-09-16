rule TTP_XOR_QUAD_CurrentVersionRun_0cc4 {
  strings:
    $key_0cc4 = { 5f ab [2] 7b a5 [2] 50 89 [2] 7e ab [2] 6a b0 [2] 65 aa [2] 7b b7 [2] 79 b6 [2] 62 b0 [2] 7e b7 [2] 62 98 }

  condition:
    any of them
}