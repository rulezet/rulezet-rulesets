rule TTP_XOR_QUAD_CurrentVersionRun_cf9f {
  strings:
    $key_cf9f = { 9c f0 [2] b8 fe [2] 93 d2 [2] bd f0 [2] a9 eb [2] a6 f1 [2] b8 ec [2] ba ed [2] a1 eb [2] bd ec [2] a1 c3 }

  condition:
    any of them
}