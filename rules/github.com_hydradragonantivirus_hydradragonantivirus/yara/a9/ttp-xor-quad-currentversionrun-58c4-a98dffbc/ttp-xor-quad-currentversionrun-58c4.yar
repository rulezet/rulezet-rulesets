rule TTP_XOR_QUAD_CurrentVersionRun_58c4 {
  strings:
    $key_58c4 = { 0b ab [2] 2f a5 [2] 04 89 [2] 2a ab [2] 3e b0 [2] 31 aa [2] 2f b7 [2] 2d b6 [2] 36 b0 [2] 2a b7 [2] 36 98 }

  condition:
    any of them
}