rule TTP_XOR_QUAD_CurrentVersionRun_10b4 {
  strings:
    $key_10b4 = { 43 db [2] 67 d5 [2] 4c f9 [2] 62 db [2] 76 c0 [2] 79 da [2] 67 c7 [2] 65 c6 [2] 7e c0 [2] 62 c7 [2] 7e e8 }

  condition:
    any of them
}