rule TTP_XOR_QUAD_CurrentVersionRun_51b4 {
  strings:
    $key_51b4 = { 02 db [2] 26 d5 [2] 0d f9 [2] 23 db [2] 37 c0 [2] 38 da [2] 26 c7 [2] 24 c6 [2] 3f c0 [2] 23 c7 [2] 3f e8 }

  condition:
    any of them
}