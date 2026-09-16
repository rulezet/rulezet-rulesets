rule TTP_XOR_QUAD_CurrentVersionRun_12b5 {
  strings:
    $key_12b5 = { 41 da [2] 65 d4 [2] 4e f8 [2] 60 da [2] 74 c1 [2] 7b db [2] 65 c6 [2] 67 c7 [2] 7c c1 [2] 60 c6 [2] 7c e9 }

  condition:
    any of them
}