rule TTP_XOR_QUAD_CurrentVersionRun_08c4 {
  strings:
    $key_08c4 = { 5b ab [2] 7f a5 [2] 54 89 [2] 7a ab [2] 6e b0 [2] 61 aa [2] 7f b7 [2] 7d b6 [2] 66 b0 [2] 7a b7 [2] 66 98 }

  condition:
    any of them
}