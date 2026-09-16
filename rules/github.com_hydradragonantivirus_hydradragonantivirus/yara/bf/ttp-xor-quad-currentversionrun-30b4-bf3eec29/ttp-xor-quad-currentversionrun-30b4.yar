rule TTP_XOR_QUAD_CurrentVersionRun_30b4 {
  strings:
    $key_30b4 = { 63 db [2] 47 d5 [2] 6c f9 [2] 42 db [2] 56 c0 [2] 59 da [2] 47 c7 [2] 45 c6 [2] 5e c0 [2] 42 c7 [2] 5e e8 }

  condition:
    any of them
}