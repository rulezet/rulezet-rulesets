rule TTP_XOR_QUAD_CurrentVersionRun_50b4 {
  strings:
    $key_50b4 = { 03 db [2] 27 d5 [2] 0c f9 [2] 22 db [2] 36 c0 [2] 39 da [2] 27 c7 [2] 25 c6 [2] 3e c0 [2] 22 c7 [2] 3e e8 }

  condition:
    any of them
}