rule TTP_XOR_QUAD_CurrentVersionRun_41b1 {
  strings:
    $key_41b1 = { 12 de [2] 36 d0 [2] 1d fc [2] 33 de [2] 27 c5 [2] 28 df [2] 36 c2 [2] 34 c3 [2] 2f c5 [2] 33 c2 [2] 2f ed }

  condition:
    any of them
}