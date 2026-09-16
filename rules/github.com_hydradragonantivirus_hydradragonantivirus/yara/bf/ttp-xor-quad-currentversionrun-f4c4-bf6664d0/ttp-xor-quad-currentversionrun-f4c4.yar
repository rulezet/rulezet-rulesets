rule TTP_XOR_QUAD_CurrentVersionRun_f4c4 {
  strings:
    $key_f4c4 = { a7 ab [2] 83 a5 [2] a8 89 [2] 86 ab [2] 92 b0 [2] 9d aa [2] 83 b7 [2] 81 b6 [2] 9a b0 [2] 86 b7 [2] 9a 98 }

  condition:
    any of them
}