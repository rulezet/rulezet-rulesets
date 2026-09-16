rule TTP_XOR_QUAD_CurrentVersionRun_daa6 {
  strings:
    $key_daa6 = { 89 c9 [2] ad c7 [2] 86 eb [2] a8 c9 [2] bc d2 [2] b3 c8 [2] ad d5 [2] af d4 [2] b4 d2 [2] a8 d5 [2] b4 fa }

  condition:
    any of them
}