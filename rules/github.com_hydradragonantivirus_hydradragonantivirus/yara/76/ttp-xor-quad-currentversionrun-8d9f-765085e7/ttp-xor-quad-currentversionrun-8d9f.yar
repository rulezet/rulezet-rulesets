rule TTP_XOR_QUAD_CurrentVersionRun_8d9f {
  strings:
    $key_8d9f = { de f0 [2] fa fe [2] d1 d2 [2] ff f0 [2] eb eb [2] e4 f1 [2] fa ec [2] f8 ed [2] e3 eb [2] ff ec [2] e3 c3 }

  condition:
    any of them
}