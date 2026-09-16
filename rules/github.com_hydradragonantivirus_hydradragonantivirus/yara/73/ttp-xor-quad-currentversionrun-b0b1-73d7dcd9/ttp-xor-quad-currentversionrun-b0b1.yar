rule TTP_XOR_QUAD_CurrentVersionRun_b0b1 {
  strings:
    $key_b0b1 = { e3 de [2] c7 d0 [2] ec fc [2] c2 de [2] d6 c5 [2] d9 df [2] c7 c2 [2] c5 c3 [2] de c5 [2] c2 c2 [2] de ed }

  condition:
    any of them
}