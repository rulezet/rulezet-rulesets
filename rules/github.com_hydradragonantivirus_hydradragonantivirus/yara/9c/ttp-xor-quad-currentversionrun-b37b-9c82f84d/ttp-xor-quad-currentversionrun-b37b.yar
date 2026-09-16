rule TTP_XOR_QUAD_CurrentVersionRun_b37b {
  strings:
    $key_b37b = { e0 14 [2] c4 1a [2] ef 36 [2] c1 14 [2] d5 0f [2] da 15 [2] c4 08 [2] c6 09 [2] dd 0f [2] c1 08 [2] dd 27 }

  condition:
    any of them
}