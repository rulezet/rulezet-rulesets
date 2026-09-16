rule TTP_XOR_QUAD_CurrentVersionRun_b32d {
  strings:
    $key_b32d = { e0 42 [2] c4 4c [2] ef 60 [2] c1 42 [2] d5 59 [2] da 43 [2] c4 5e [2] c6 5f [2] dd 59 [2] c1 5e [2] dd 71 }

  condition:
    any of them
}