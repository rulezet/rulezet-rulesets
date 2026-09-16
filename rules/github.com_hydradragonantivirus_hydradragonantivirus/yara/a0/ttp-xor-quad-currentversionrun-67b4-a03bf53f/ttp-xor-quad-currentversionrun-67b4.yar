rule TTP_XOR_QUAD_CurrentVersionRun_67b4 {
  strings:
    $key_67b4 = { 34 db [2] 10 d5 [2] 3b f9 [2] 15 db [2] 01 c0 [2] 0e da [2] 10 c7 [2] 12 c6 [2] 09 c0 [2] 15 c7 [2] 09 e8 }

  condition:
    any of them
}