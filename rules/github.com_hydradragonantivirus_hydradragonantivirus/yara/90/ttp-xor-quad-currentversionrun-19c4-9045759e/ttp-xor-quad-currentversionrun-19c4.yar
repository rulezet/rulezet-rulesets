rule TTP_XOR_QUAD_CurrentVersionRun_19c4 {
  strings:
    $key_19c4 = { 4a ab [2] 6e a5 [2] 45 89 [2] 6b ab [2] 7f b0 [2] 70 aa [2] 6e b7 [2] 6c b6 [2] 77 b0 [2] 6b b7 [2] 77 98 }

  condition:
    any of them
}