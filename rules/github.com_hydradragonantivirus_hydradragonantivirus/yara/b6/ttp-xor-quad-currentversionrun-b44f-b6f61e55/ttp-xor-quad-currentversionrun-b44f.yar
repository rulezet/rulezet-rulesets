rule TTP_XOR_QUAD_CurrentVersionRun_b44f {
  strings:
    $key_b44f = { e7 20 [2] c3 2e [2] e8 02 [2] c6 20 [2] d2 3b [2] dd 21 [2] c3 3c [2] c1 3d [2] da 3b [2] c6 3c [2] da 13 }

  condition:
    any of them
}