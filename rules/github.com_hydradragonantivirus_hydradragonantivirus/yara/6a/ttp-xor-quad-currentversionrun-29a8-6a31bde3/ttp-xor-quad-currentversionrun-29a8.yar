rule TTP_XOR_QUAD_CurrentVersionRun_29a8 {
  strings:
    $key_29a8 = { 7a c7 [2] 5e c9 [2] 75 e5 [2] 5b c7 [2] 4f dc [2] 40 c6 [2] 5e db [2] 5c da [2] 47 dc [2] 5b db [2] 47 f4 }

  condition:
    any of them
}