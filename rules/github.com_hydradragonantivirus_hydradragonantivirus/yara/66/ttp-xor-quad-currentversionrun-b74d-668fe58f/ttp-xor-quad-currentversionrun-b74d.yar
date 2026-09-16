rule TTP_XOR_QUAD_CurrentVersionRun_b74d {
  strings:
    $key_b74d = { e4 22 [2] c0 2c [2] eb 00 [2] c5 22 [2] d1 39 [2] de 23 [2] c0 3e [2] c2 3f [2] d9 39 [2] c5 3e [2] d9 11 }

  condition:
    any of them
}