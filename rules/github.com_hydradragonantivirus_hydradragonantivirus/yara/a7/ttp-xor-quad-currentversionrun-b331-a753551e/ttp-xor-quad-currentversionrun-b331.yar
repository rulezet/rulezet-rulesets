rule TTP_XOR_QUAD_CurrentVersionRun_b331 {
  strings:
    $key_b331 = { e0 5e [2] c4 50 [2] ef 7c [2] c1 5e [2] d5 45 [2] da 5f [2] c4 42 [2] c6 43 [2] dd 45 [2] c1 42 [2] dd 6d }

  condition:
    any of them
}