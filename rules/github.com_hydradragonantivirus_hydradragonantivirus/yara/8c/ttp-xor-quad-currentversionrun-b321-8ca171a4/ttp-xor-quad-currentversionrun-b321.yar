rule TTP_XOR_QUAD_CurrentVersionRun_b321 {
  strings:
    $key_b321 = { e0 4e [2] c4 40 [2] ef 6c [2] c1 4e [2] d5 55 [2] da 4f [2] c4 52 [2] c6 53 [2] dd 55 [2] c1 52 [2] dd 7d }

  condition:
    any of them
}