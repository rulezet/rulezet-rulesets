rule TTP_XOR_QUAD_CurrentVersionRun_1cc4 {
  strings:
    $key_1cc4 = { 4f ab [2] 6b a5 [2] 40 89 [2] 6e ab [2] 7a b0 [2] 75 aa [2] 6b b7 [2] 69 b6 [2] 72 b0 [2] 6e b7 [2] 72 98 }

  condition:
    any of them
}