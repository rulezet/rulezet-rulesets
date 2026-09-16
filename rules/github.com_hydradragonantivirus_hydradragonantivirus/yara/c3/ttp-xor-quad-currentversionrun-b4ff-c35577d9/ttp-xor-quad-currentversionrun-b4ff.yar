rule TTP_XOR_QUAD_CurrentVersionRun_b4ff {
  strings:
    $key_b4ff = { e7 90 [2] c3 9e [2] e8 b2 [2] c6 90 [2] d2 8b [2] dd 91 [2] c3 8c [2] c1 8d [2] da 8b [2] c6 8c [2] da a3 }

  condition:
    any of them
}