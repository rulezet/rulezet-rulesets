rule TTP_XOR_QUAD_CurrentVersionRun_2db5 {
  strings:
    $key_2db5 = { 7e da [2] 5a d4 [2] 71 f8 [2] 5f da [2] 4b c1 [2] 44 db [2] 5a c6 [2] 58 c7 [2] 43 c1 [2] 5f c6 [2] 43 e9 }

  condition:
    any of them
}