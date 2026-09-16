rule TTP_XOR_QUAD_CurrentVersionRun_18c4 {
  strings:
    $key_18c4 = { 4b ab [2] 6f a5 [2] 44 89 [2] 6a ab [2] 7e b0 [2] 71 aa [2] 6f b7 [2] 6d b6 [2] 76 b0 [2] 6a b7 [2] 76 98 }

  condition:
    any of them
}