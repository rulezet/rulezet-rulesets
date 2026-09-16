rule TTP_XOR_QUAD_CurrentVersionRun_48c4 {
  strings:
    $key_48c4 = { 1b ab [2] 3f a5 [2] 14 89 [2] 3a ab [2] 2e b0 [2] 21 aa [2] 3f b7 [2] 3d b6 [2] 26 b0 [2] 3a b7 [2] 26 98 }

  condition:
    any of them
}