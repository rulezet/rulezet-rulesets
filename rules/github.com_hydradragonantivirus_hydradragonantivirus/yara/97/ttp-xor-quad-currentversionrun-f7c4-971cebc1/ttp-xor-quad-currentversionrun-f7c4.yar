rule TTP_XOR_QUAD_CurrentVersionRun_f7c4 {
  strings:
    $key_f7c4 = { a4 ab [2] 80 a5 [2] ab 89 [2] 85 ab [2] 91 b0 [2] 9e aa [2] 80 b7 [2] 82 b6 [2] 99 b0 [2] 85 b7 [2] 99 98 }

  condition:
    any of them
}