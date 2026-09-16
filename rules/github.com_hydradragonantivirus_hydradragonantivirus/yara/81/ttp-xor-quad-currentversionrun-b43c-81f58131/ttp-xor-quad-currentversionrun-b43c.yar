rule TTP_XOR_QUAD_CurrentVersionRun_b43c {
  strings:
    $key_b43c = { e7 53 [2] c3 5d [2] e8 71 [2] c6 53 [2] d2 48 [2] dd 52 [2] c3 4f [2] c1 4e [2] da 48 [2] c6 4f [2] da 60 }

  condition:
    any of them
}