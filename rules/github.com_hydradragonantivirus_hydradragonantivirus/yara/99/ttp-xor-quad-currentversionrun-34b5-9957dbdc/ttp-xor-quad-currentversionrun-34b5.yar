rule TTP_XOR_QUAD_CurrentVersionRun_34b5 {
  strings:
    $key_34b5 = { 67 da [2] 43 d4 [2] 68 f8 [2] 46 da [2] 52 c1 [2] 5d db [2] 43 c6 [2] 41 c7 [2] 5a c1 [2] 46 c6 [2] 5a e9 }

  condition:
    any of them
}