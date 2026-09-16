rule TTP_XOR_QUAD_CurrentVersionRun_17d8 {
  strings:
    $key_17d8 = { 44 b7 [2] 60 b9 [2] 4b 95 [2] 65 b7 [2] 71 ac [2] 7e b6 [2] 60 ab [2] 62 aa [2] 79 ac [2] 65 ab [2] 79 84 }

  condition:
    any of them
}