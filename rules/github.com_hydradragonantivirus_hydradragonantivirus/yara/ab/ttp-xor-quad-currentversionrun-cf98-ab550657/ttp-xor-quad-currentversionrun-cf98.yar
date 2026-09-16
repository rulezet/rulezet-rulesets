rule TTP_XOR_QUAD_CurrentVersionRun_cf98 {
  strings:
    $key_cf98 = { 9c f7 [2] b8 f9 [2] 93 d5 [2] bd f7 [2] a9 ec [2] a6 f6 [2] b8 eb [2] ba ea [2] a1 ec [2] bd eb [2] a1 c4 }

  condition:
    any of them
}