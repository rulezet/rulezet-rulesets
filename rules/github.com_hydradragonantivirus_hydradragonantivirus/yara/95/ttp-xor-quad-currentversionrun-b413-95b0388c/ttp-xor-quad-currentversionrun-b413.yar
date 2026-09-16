rule TTP_XOR_QUAD_CurrentVersionRun_b413 {
  strings:
    $key_b413 = { e7 7c [2] c3 72 [2] e8 5e [2] c6 7c [2] d2 67 [2] dd 7d [2] c3 60 [2] c1 61 [2] da 67 [2] c6 60 [2] da 4f }

  condition:
    any of them
}