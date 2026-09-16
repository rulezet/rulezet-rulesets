rule TTP_XOR_QUAD_CurrentVersionRun_f3b1 {
  strings:
    $key_f3b1 = { a0 de [2] 84 d0 [2] af fc [2] 81 de [2] 95 c5 [2] 9a df [2] 84 c2 [2] 86 c3 [2] 9d c5 [2] 81 c2 [2] 9d ed }

  condition:
    any of them
}