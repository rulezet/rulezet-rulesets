rule TTP_XOR_QUAD_CurrentVersionRun_2bd7 {
  strings:
    $key_2bd7 = { 78 b8 [2] 5c b6 [2] 77 9a [2] 59 b8 [2] 4d a3 [2] 42 b9 [2] 5c a4 [2] 5e a5 [2] 45 a3 [2] 59 a4 [2] 45 8b }

  condition:
    any of them
}