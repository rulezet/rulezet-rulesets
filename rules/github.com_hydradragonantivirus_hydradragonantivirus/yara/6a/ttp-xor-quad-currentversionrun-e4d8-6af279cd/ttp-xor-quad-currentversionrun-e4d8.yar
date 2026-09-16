rule TTP_XOR_QUAD_CurrentVersionRun_e4d8 {
  strings:
    $key_e4d8 = { b7 b7 [2] 93 b9 [2] b8 95 [2] 96 b7 [2] 82 ac [2] 8d b6 [2] 93 ab [2] 91 aa [2] 8a ac [2] 96 ab [2] 8a 84 }

  condition:
    any of them
}