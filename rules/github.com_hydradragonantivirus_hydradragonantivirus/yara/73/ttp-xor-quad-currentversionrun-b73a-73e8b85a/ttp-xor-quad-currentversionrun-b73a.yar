rule TTP_XOR_QUAD_CurrentVersionRun_b73a {
  strings:
    $key_b73a = { e4 55 [2] c0 5b [2] eb 77 [2] c5 55 [2] d1 4e [2] de 54 [2] c0 49 [2] c2 48 [2] d9 4e [2] c5 49 [2] d9 66 }

  condition:
    any of them
}