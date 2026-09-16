rule TTP_XOR_QUAD_CurrentVersionRun_b650 {
  strings:
    $key_b650 = { e5 3f [2] c1 31 [2] ea 1d [2] c4 3f [2] d0 24 [2] df 3e [2] c1 23 [2] c3 22 [2] d8 24 [2] c4 23 [2] d8 0c }

  condition:
    any of them
}