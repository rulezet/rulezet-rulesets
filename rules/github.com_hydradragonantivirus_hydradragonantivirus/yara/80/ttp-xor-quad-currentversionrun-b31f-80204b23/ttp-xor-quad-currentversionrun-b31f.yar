rule TTP_XOR_QUAD_CurrentVersionRun_b31f {
  strings:
    $key_b31f = { e0 70 [2] c4 7e [2] ef 52 [2] c1 70 [2] d5 6b [2] da 71 [2] c4 6c [2] c6 6d [2] dd 6b [2] c1 6c [2] dd 43 }

  condition:
    any of them
}