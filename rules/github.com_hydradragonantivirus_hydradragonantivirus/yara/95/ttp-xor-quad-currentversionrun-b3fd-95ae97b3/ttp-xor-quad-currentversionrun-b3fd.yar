rule TTP_XOR_QUAD_CurrentVersionRun_b3fd {
  strings:
    $key_b3fd = { e0 92 [2] c4 9c [2] ef b0 [2] c1 92 [2] d5 89 [2] da 93 [2] c4 8e [2] c6 8f [2] dd 89 [2] c1 8e [2] dd a1 }

  condition:
    any of them
}