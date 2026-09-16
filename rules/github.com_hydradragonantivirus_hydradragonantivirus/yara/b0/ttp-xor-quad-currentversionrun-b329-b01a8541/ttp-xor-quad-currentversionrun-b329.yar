rule TTP_XOR_QUAD_CurrentVersionRun_b329 {
  strings:
    $key_b329 = { e0 46 [2] c4 48 [2] ef 64 [2] c1 46 [2] d5 5d [2] da 47 [2] c4 5a [2] c6 5b [2] dd 5d [2] c1 5a [2] dd 75 }

  condition:
    any of them
}