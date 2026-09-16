rule TTP_XOR_QUAD_CurrentVersionRun_b69f {
  strings:
    $key_b69f = { e5 f0 [2] c1 fe [2] ea d2 [2] c4 f0 [2] d0 eb [2] df f1 [2] c1 ec [2] c3 ed [2] d8 eb [2] c4 ec [2] d8 c3 }

  condition:
    any of them
}