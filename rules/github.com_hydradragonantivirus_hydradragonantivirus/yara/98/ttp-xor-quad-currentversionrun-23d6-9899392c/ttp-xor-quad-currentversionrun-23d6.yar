rule TTP_XOR_QUAD_CurrentVersionRun_23d6 {
  strings:
    $key_23d6 = { 70 b9 [2] 54 b7 [2] 7f 9b [2] 51 b9 [2] 45 a2 [2] 4a b8 [2] 54 a5 [2] 56 a4 [2] 4d a2 [2] 51 a5 [2] 4d 8a }

  condition:
    any of them
}