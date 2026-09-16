rule TTP_XOR_QUAD_CurrentVersionRun_b74a {
  strings:
    $key_b74a = { e4 25 [2] c0 2b [2] eb 07 [2] c5 25 [2] d1 3e [2] de 24 [2] c0 39 [2] c2 38 [2] d9 3e [2] c5 39 [2] d9 16 }

  condition:
    any of them
}