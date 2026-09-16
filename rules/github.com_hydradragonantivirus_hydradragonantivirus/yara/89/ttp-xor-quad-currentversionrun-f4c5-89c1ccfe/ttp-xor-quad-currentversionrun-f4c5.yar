rule TTP_XOR_QUAD_CurrentVersionRun_f4c5 {
  strings:
    $key_f4c5 = { a7 aa [2] 83 a4 [2] a8 88 [2] 86 aa [2] 92 b1 [2] 9d ab [2] 83 b6 [2] 81 b7 [2] 9a b1 [2] 86 b6 [2] 9a 99 }

  condition:
    any of them
}