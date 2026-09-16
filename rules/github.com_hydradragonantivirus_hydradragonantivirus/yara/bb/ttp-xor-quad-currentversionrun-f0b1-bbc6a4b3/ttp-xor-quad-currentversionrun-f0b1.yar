rule TTP_XOR_QUAD_CurrentVersionRun_f0b1 {
  strings:
    $key_f0b1 = { a3 de [2] 87 d0 [2] ac fc [2] 82 de [2] 96 c5 [2] 99 df [2] 87 c2 [2] 85 c3 [2] 9e c5 [2] 82 c2 [2] 9e ed }

  condition:
    any of them
}