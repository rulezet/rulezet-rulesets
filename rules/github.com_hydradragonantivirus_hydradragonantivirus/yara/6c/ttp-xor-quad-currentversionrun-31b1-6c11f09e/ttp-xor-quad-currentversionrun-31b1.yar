rule TTP_XOR_QUAD_CurrentVersionRun_31b1 {
  strings:
    $key_31b1 = { 62 de [2] 46 d0 [2] 6d fc [2] 43 de [2] 57 c5 [2] 58 df [2] 46 c2 [2] 44 c3 [2] 5f c5 [2] 43 c2 [2] 5f ed }

  condition:
    any of them
}