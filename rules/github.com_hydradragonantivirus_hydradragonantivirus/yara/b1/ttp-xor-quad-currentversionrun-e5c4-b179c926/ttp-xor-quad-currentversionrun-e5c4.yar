rule TTP_XOR_QUAD_CurrentVersionRun_e5c4 {
  strings:
    $key_e5c4 = { b6 ab [2] 92 a5 [2] b9 89 [2] 97 ab [2] 83 b0 [2] 8c aa [2] 92 b7 [2] 90 b6 [2] 8b b0 [2] 97 b7 [2] 8b 98 }

  condition:
    any of them
}