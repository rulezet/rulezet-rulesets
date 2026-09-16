rule TTP_XOR_QUAD_CurrentVersionRun_15b5 {
  strings:
    $key_15b5 = { 46 da [2] 62 d4 [2] 49 f8 [2] 67 da [2] 73 c1 [2] 7c db [2] 62 c6 [2] 60 c7 [2] 7b c1 [2] 67 c6 [2] 7b e9 }

  condition:
    any of them
}