rule TTP_XOR_QUAD_CurrentVersionRun_b73d {
  strings:
    $key_b73d = { e4 52 [2] c0 5c [2] eb 70 [2] c5 52 [2] d1 49 [2] de 53 [2] c0 4e [2] c2 4f [2] d9 49 [2] c5 4e [2] d9 61 }

  condition:
    any of them
}