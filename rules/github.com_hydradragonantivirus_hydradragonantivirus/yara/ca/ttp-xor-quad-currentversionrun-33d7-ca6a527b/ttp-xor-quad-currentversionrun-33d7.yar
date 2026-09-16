rule TTP_XOR_QUAD_CurrentVersionRun_33d7 {
  strings:
    $key_33d7 = { 60 b8 [2] 44 b6 [2] 6f 9a [2] 41 b8 [2] 55 a3 [2] 5a b9 [2] 44 a4 [2] 46 a5 [2] 5d a3 [2] 41 a4 [2] 5d 8b }

  condition:
    any of them
}