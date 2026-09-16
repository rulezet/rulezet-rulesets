rule TTP_XOR_QUAD_CurrentVersionRun_f1d8 {
  strings:
    $key_f1d8 = { a2 b7 [2] 86 b9 [2] ad 95 [2] 83 b7 [2] 97 ac [2] 98 b6 [2] 86 ab [2] 84 aa [2] 9f ac [2] 83 ab [2] 9f 84 }

  condition:
    any of them
}