rule TTP_XOR_QUAD_CurrentVersionRun_f4b5 {
  strings:
    $key_f4b5 = { a7 da [2] 83 d4 [2] a8 f8 [2] 86 da [2] 92 c1 [2] 9d db [2] 83 c6 [2] 81 c7 [2] 9a c1 [2] 86 c6 [2] 9a e9 }

  condition:
    any of them
}