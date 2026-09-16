rule TTP_XOR_QUAD_CurrentVersionRun_12d7 {
  strings:
    $key_12d7 = { 41 b8 [2] 65 b6 [2] 4e 9a [2] 60 b8 [2] 74 a3 [2] 7b b9 [2] 65 a4 [2] 67 a5 [2] 7c a3 [2] 60 a4 [2] 7c 8b }

  condition:
    any of them
}