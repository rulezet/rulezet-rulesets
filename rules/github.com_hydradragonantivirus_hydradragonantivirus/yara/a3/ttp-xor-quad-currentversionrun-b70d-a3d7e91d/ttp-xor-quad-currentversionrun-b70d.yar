rule TTP_XOR_QUAD_CurrentVersionRun_b70d {
  strings:
    $key_b70d = { e4 62 [2] c0 6c [2] eb 40 [2] c5 62 [2] d1 79 [2] de 63 [2] c0 7e [2] c2 7f [2] d9 79 [2] c5 7e [2] d9 51 }

  condition:
    any of them
}