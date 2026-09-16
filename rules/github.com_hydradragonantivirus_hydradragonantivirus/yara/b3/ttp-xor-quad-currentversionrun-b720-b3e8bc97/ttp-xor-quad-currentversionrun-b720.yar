rule TTP_XOR_QUAD_CurrentVersionRun_b720 {
  strings:
    $key_b720 = { e4 4f [2] c0 41 [2] eb 6d [2] c5 4f [2] d1 54 [2] de 4e [2] c0 53 [2] c2 52 [2] d9 54 [2] c5 53 [2] d9 7c }

  condition:
    any of them
}