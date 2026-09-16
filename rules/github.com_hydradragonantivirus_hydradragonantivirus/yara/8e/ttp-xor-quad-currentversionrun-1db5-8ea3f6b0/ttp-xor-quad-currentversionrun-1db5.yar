rule TTP_XOR_QUAD_CurrentVersionRun_1db5 {
  strings:
    $key_1db5 = { 4e da [2] 6a d4 [2] 41 f8 [2] 6f da [2] 7b c1 [2] 74 db [2] 6a c6 [2] 68 c7 [2] 73 c1 [2] 6f c6 [2] 73 e9 }

  condition:
    any of them
}