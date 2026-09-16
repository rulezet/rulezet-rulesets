rule TTP_XOR_QUAD_CurrentVersionRun_f0d8 {
  strings:
    $key_f0d8 = { a3 b7 [2] 87 b9 [2] ac 95 [2] 82 b7 [2] 96 ac [2] 99 b6 [2] 87 ab [2] 85 aa [2] 9e ac [2] 82 ab [2] 9e 84 }

  condition:
    any of them
}