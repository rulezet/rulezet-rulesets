rule TTP_XOR_QUAD_CurrentVersionRun_31c5 {
  strings:
    $key_31c5 = { 62 aa [2] 46 a4 [2] 6d 88 [2] 43 aa [2] 57 b1 [2] 58 ab [2] 46 b6 [2] 44 b7 [2] 5f b1 [2] 43 b6 [2] 5f 99 }

  condition:
    any of them
}