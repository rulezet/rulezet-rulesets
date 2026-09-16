rule TTP_XOR_QUAD_CurrentVersionRun_50b5 {
  strings:
    $key_50b5 = { 03 da [2] 27 d4 [2] 0c f8 [2] 22 da [2] 36 c1 [2] 39 db [2] 27 c6 [2] 25 c7 [2] 3e c1 [2] 22 c6 [2] 3e e9 }

  condition:
    any of them
}