rule TTP_XOR_QUAD_CurrentVersionRun_4bd7 {
  strings:
    $key_4bd7 = { 18 b8 [2] 3c b6 [2] 17 9a [2] 39 b8 [2] 2d a3 [2] 22 b9 [2] 3c a4 [2] 3e a5 [2] 25 a3 [2] 39 a4 [2] 25 8b }

  condition:
    any of them
}