rule TTP_XOR_QUAD_CurrentVersionRun_3ab5 {
  strings:
    $key_3ab5 = { 69 da [2] 4d d4 [2] 66 f8 [2] 48 da [2] 5c c1 [2] 53 db [2] 4d c6 [2] 4f c7 [2] 54 c1 [2] 48 c6 [2] 54 e9 }

  condition:
    any of them
}