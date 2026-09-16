rule TTP_XOR_QUAD_CurrentVersionRun_d49f {
  strings:
    $key_d49f = { 87 f0 [2] a3 fe [2] 88 d2 [2] a6 f0 [2] b2 eb [2] bd f1 [2] a3 ec [2] a1 ed [2] ba eb [2] a6 ec [2] ba c3 }

  condition:
    any of them
}