rule TTP_XOR_QUAD_CurrentVersionRun_21d8 {
  strings:
    $key_21d8 = { 72 b7 [2] 56 b9 [2] 7d 95 [2] 53 b7 [2] 47 ac [2] 48 b6 [2] 56 ab [2] 54 aa [2] 4f ac [2] 53 ab [2] 4f 84 }

  condition:
    any of them
}