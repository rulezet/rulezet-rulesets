rule TTP_XOR_QUAD_CurrentVersionRun_30d7 {
  strings:
    $key_30d7 = { 63 b8 [2] 47 b6 [2] 6c 9a [2] 42 b8 [2] 56 a3 [2] 59 b9 [2] 47 a4 [2] 45 a5 [2] 5e a3 [2] 42 a4 [2] 5e 8b }

  condition:
    any of them
}