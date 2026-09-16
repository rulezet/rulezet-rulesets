rule TTP_XOR_QUAD_CurrentVersionRun_49c4 {
  strings:
    $key_49c4 = { 1a ab [2] 3e a5 [2] 15 89 [2] 3b ab [2] 2f b0 [2] 20 aa [2] 3e b7 [2] 3c b6 [2] 27 b0 [2] 3b b7 [2] 27 98 }

  condition:
    any of them
}