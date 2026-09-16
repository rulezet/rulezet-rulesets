rule TTP_XOR_QUAD_CurrentVersionRun_efb4 {
  strings:
    $key_efb4 = { bc db [2] 98 d5 [2] b3 f9 [2] 9d db [2] 89 c0 [2] 86 da [2] 98 c7 [2] 9a c6 [2] 81 c0 [2] 9d c7 [2] 81 e8 }

  condition:
    any of them
}