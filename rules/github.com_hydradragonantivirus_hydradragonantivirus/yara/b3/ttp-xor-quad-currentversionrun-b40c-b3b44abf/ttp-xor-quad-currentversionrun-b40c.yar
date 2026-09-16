rule TTP_XOR_QUAD_CurrentVersionRun_b40c {
  strings:
    $key_b40c = { e7 63 [2] c3 6d [2] e8 41 [2] c6 63 [2] d2 78 [2] dd 62 [2] c3 7f [2] c1 7e [2] da 78 [2] c6 7f [2] da 50 }

  condition:
    any of them
}