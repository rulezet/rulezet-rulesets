rule TTP_XOR_QUAD_CurrentVersionRun_77b4 {
  strings:
    $key_77b4 = { 24 db [2] 00 d5 [2] 2b f9 [2] 05 db [2] 11 c0 [2] 1e da [2] 00 c7 [2] 02 c6 [2] 19 c0 [2] 05 c7 [2] 19 e8 }

  condition:
    any of them
}