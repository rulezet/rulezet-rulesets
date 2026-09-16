rule TTP_XOR_QUAD_CurrentVersionRun_b32a {
  strings:
    $key_b32a = { e0 45 [2] c4 4b [2] ef 67 [2] c1 45 [2] d5 5e [2] da 44 [2] c4 59 [2] c6 58 [2] dd 5e [2] c1 59 [2] dd 76 }

  condition:
    any of them
}