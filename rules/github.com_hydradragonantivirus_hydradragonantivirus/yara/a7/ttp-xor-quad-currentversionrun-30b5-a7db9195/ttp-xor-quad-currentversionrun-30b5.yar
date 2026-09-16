rule TTP_XOR_QUAD_CurrentVersionRun_30b5 {
  strings:
    $key_30b5 = { 63 da [2] 47 d4 [2] 6c f8 [2] 42 da [2] 56 c1 [2] 59 db [2] 47 c6 [2] 45 c7 [2] 5e c1 [2] 42 c6 [2] 5e e9 }

  condition:
    any of them
}