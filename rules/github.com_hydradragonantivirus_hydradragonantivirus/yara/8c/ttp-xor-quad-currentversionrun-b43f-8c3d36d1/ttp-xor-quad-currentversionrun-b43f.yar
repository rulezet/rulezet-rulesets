rule TTP_XOR_QUAD_CurrentVersionRun_b43f {
  strings:
    $key_b43f = { e7 50 [2] c3 5e [2] e8 72 [2] c6 50 [2] d2 4b [2] dd 51 [2] c3 4c [2] c1 4d [2] da 4b [2] c6 4c [2] da 63 }

  condition:
    any of them
}