rule TTP_XOR_QUAD_CurrentVersionRun_f2d9 {
  strings:
    $key_f2d9 = { a1 b6 [2] 85 b8 [2] ae 94 [2] 80 b6 [2] 94 ad [2] 9b b7 [2] 85 aa [2] 87 ab [2] 9c ad [2] 80 aa [2] 9c 85 }

  condition:
    any of them
}