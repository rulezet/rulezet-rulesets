rule TTP_XOR_QUAD_CurrentVersionRun_50c4 {
  strings:
    $key_50c4 = { 03 ab [2] 27 a5 [2] 0c 89 [2] 22 ab [2] 36 b0 [2] 39 aa [2] 27 b7 [2] 25 b6 [2] 3e b0 [2] 22 b7 [2] 3e 98 }

  condition:
    any of them
}