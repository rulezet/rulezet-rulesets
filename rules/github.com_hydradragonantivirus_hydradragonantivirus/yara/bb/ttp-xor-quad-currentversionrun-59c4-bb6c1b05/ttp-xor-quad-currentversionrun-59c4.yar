rule TTP_XOR_QUAD_CurrentVersionRun_59c4 {
  strings:
    $key_59c4 = { 0a ab [2] 2e a5 [2] 05 89 [2] 2b ab [2] 3f b0 [2] 30 aa [2] 2e b7 [2] 2c b6 [2] 37 b0 [2] 2b b7 [2] 37 98 }

  condition:
    any of them
}