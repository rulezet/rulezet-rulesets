rule TTP_XOR_QUAD_CurrentVersionRun_24b5 {
  strings:
    $key_24b5 = { 77 da [2] 53 d4 [2] 78 f8 [2] 56 da [2] 42 c1 [2] 4d db [2] 53 c6 [2] 51 c7 [2] 4a c1 [2] 56 c6 [2] 4a e9 }

  condition:
    any of them
}