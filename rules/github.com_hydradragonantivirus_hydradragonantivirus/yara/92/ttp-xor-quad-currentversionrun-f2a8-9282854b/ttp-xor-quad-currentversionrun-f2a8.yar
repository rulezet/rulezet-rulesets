rule TTP_XOR_QUAD_CurrentVersionRun_f2a8 {
  strings:
    $key_f2a8 = { a1 c7 [2] 85 c9 [2] ae e5 [2] 80 c7 [2] 94 dc [2] 9b c6 [2] 85 db [2] 87 da [2] 9c dc [2] 80 db [2] 9c f4 }

  condition:
    any of them
}