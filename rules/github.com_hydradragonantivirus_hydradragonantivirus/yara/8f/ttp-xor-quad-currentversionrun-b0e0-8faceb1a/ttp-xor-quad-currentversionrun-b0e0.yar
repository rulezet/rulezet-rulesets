rule TTP_XOR_QUAD_CurrentVersionRun_b0e0 {
  strings:
    $key_b0e0 = { e3 8f [2] c7 81 [2] ec ad [2] c2 8f [2] d6 94 [2] d9 8e [2] c7 93 [2] c5 92 [2] de 94 [2] c2 93 [2] de bc }

  condition:
    any of them
}