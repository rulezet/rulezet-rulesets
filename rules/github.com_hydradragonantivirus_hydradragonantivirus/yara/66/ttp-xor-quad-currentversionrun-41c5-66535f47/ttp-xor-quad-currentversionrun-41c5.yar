rule TTP_XOR_QUAD_CurrentVersionRun_41c5 {
  strings:
    $key_41c5 = { 12 aa [2] 36 a4 [2] 1d 88 [2] 33 aa [2] 27 b1 [2] 28 ab [2] 36 b6 [2] 34 b7 [2] 2f b1 [2] 33 b6 [2] 2f 99 }

  condition:
    any of them
}