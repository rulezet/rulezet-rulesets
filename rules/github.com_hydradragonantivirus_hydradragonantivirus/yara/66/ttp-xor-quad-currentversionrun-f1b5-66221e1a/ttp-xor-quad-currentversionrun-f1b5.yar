rule TTP_XOR_QUAD_CurrentVersionRun_f1b5 {
  strings:
    $key_f1b5 = { a2 da [2] 86 d4 [2] ad f8 [2] 83 da [2] 97 c1 [2] 98 db [2] 86 c6 [2] 84 c7 [2] 9f c1 [2] 83 c6 [2] 9f e9 }

  condition:
    any of them
}