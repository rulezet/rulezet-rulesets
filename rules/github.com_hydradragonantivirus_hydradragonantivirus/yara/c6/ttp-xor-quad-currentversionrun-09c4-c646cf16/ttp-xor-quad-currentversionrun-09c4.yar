rule TTP_XOR_QUAD_CurrentVersionRun_09c4 {
  strings:
    $key_09c4 = { 5a ab [2] 7e a5 [2] 55 89 [2] 7b ab [2] 6f b0 [2] 60 aa [2] 7e b7 [2] 7c b6 [2] 67 b0 [2] 7b b7 [2] 67 98 }

  condition:
    any of them
}